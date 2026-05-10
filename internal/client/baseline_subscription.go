package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"vigilprotector.io/vp-lib/baselines"
	vplogging "vigilprotector.io/vp-lib/logging"
)

// SubscribingBaselineProvider replaces the historic TTL-driven
// BaselineCache (SS-BP-004 / VP-2225). It satisfies BaselineProvider but
// the underlying data comes from a pull-cursor subscription on
// StratoSage, not from an on-demand HTTP poll: a background goroutine
// drains baselines.BaselineSubscription, applies published envelopes to
// an in-memory map, and evicts the slot when an Action=invalidated
// envelope arrives. GetBaseline is a constant-time map read — no
// cache-miss path, no TTL, no hidden HTTP request.
//
// This shape solves three audit findings at once:
//
//   - NH-LM-003 (VP-2233): the lateral-movement detector keeps depending
//     on BaselineProvider; the subscription-backed implementation lets
//     it consume StratoSage baselines without re-running detection on
//     stale TTL'd snapshots.
//   - SS-BP-004 (VP-2225): the consumer is a real pull-cursor subscriber
//     rather than a TTL HTTP cache.
//   - Sprint-14 Pattern C ("Pseudo-Implementation"): the artifact's name
//     matches what it actually does.
type SubscribingBaselineProvider struct {
	mu      sync.RWMutex
	entries map[string]*Baseline

	subscription Subscription
	logger       logr.Logger
	retryDelay   time.Duration
}

// Subscription is the narrow port SubscribingBaselineProvider depends
// on. It matches vp-lib/baselines.BaselineSubscription so a
// baselines/pullcursor.SubscriptionClient drops in unchanged and tests
// can swap in a fake without a live HTTP endpoint.
type Subscription interface {
	Next(ctx context.Context) (baselines.Envelope, baselines.Ack, error)
	Close() error
}

// SubscribingBaselineProviderConfig configures a SubscribingBaselineProvider.
type SubscribingBaselineProviderConfig struct {
	Subscription Subscription
	Logger       logr.Logger

	// RetryDelay is the wait between consecutive Next failures. Defaults
	// to 5 seconds. Zero is treated as default.
	RetryDelay time.Duration
}

// ErrMissingSubscription is returned by NewSubscribingBaselineProvider
// when cfg.Subscription is nil.
var ErrMissingSubscription = errors.New("client: SubscribingBaselineProvider requires Subscription")

// NewSubscribingBaselineProvider constructs a provider. The subscription
// MUST be non-nil. Call Run on the returned provider to start draining
// the subscription; bind its context to the server lifecycle so
// shutdown propagates.
func NewSubscribingBaselineProvider(cfg SubscribingBaselineProviderConfig) (*SubscribingBaselineProvider, error) {
	if cfg.Subscription == nil {
		return nil, ErrMissingSubscription
	}

	if cfg.Logger == (logr.Logger{}) {
		cfg.Logger = logr.Discard()
	}

	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = 5 * time.Second
	}

	return &SubscribingBaselineProvider{
		entries:      make(map[string]*Baseline),
		subscription: cfg.Subscription,
		logger:       cfg.Logger.WithName("baseline-subscriber"),
		retryDelay:   cfg.RetryDelay,
	}, nil
}

// Run drains the subscription and updates the in-memory map until ctx is
// cancelled. Transient Next errors are logged and backed off; the loop
// continues so a temporary StratoSage outage does not poison the
// provider — GetBaseline keeps serving the last known state.
func (p *SubscribingBaselineProvider) Run(ctx context.Context) error {
	p.logger.Info("baseline subscription consumer starting")

	defer func() {
		if err := p.subscription.Close(); err != nil {
			p.logger.Error(err, "failed to close baseline subscription")
		}
	}()

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			p.logger.Info("baseline subscription consumer stopping (context done)")

			return nil
		}

		env, ack, err := p.subscription.Next(ctx)
		if err != nil {
			if errors.Is(err, baselines.ErrSubscriptionClosed) {
				p.logger.Info("baseline subscription closed by owner")

				return nil
			}

			// Only the parent context being cancelled is grounds to
			// terminate the consumer. A bare DeadlineExceeded on the
			// returned error can come from a transient HTTP client
			// timeout (slow stratosage poll) while ctx itself is
			// still healthy — exiting in that case strands the
			// subscriber and the detector runs on stale baselines
			// indefinitely. Re-check ctx, then back-off+retry.
			if ctx.Err() != nil {
				return nil
			}

			p.logger.Error(err, "baseline subscription Next failed; backing off",
				"transient", errors.Is(err, context.DeadlineExceeded))

			if waitErr := waitOrCancel(ctx, p.retryDelay); waitErr != nil {
				return nil
			}

			continue
		}

		p.apply(env)

		if ackErr := ack(ctx); ackErr != nil {
			p.logger.Error(ackErr, "failed to ack baseline envelope",
				"baselineId", env.BaselineID,
				"action", string(env.Action),
			)
		}
	}
}

// GetBaseline returns the cached baseline for (scopeRef, featureSet),
// or (nil, nil) when nothing has been subscribed yet. The "missing"
// case is the existing BaselineProvider contract — callers (the lateral
// movement detector in particular) treat nil as "fall back to local
// heuristic".
func (p *SubscribingBaselineProvider) GetBaseline(
	_ context.Context,
	scopeRef string,
	featureSet string,
) (*Baseline, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	entry, ok := p.entries[cacheKey(scopeRef, featureSet)]
	if !ok {
		return nil, nil
	}

	return entry, nil
}

// GetBaselinesForScope returns every cached baseline whose ScopeRef
// equals scopeRef. The BaselineProvider contract for this method is the
// historic "no-cache list query"; here every entry is already local so
// we just filter the map.
func (p *SubscribingBaselineProvider) GetBaselinesForScope(
	_ context.Context,
	scopeRef string,
) ([]*Baseline, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]*Baseline, 0)

	for _, entry := range p.entries {
		if entry.ScopeRef == scopeRef {
			out = append(out, entry)
		}
	}

	return out, nil
}

func (p *SubscribingBaselineProvider) apply(env baselines.Envelope) {
	switch env.Action {
	case baselines.ActionPublished:
		p.upsert(env)
	case baselines.ActionInvalidated:
		p.remove(env.ScopeRef, env.FeatureSet)
	default:
		p.logger.V(vplogging.LogLevelInfo).Info("ignoring baseline envelope with unknown action",
			"baselineId", env.BaselineID,
			"action", string(env.Action),
		)
	}
}

func (p *SubscribingBaselineProvider) upsert(env baselines.Envelope) {
	stats := make(map[string]float64, len(env.SummaryStats))
	for k, v := range env.SummaryStats {
		stats[k] = v
	}

	validUntil := env.ValidTo

	entry := &Baseline{
		ID:           env.BaselineID,
		ScopeRef:     env.ScopeRef,
		FeatureSet:   env.FeatureSet,
		Stats:        stats,
		ModelVersion: env.ModelVersion,
		ValidFrom:    env.ValidFrom,
		ValidUntil:   validUntil,
		Metadata:     env.Metadata,
	}

	p.mu.Lock()
	p.entries[cacheKey(env.ScopeRef, env.FeatureSet)] = entry
	p.mu.Unlock()

	p.logger.V(vplogging.LogLevelDebug).Info("baseline cached from subscription",
		"baselineId", env.BaselineID,
		"scopeRef", env.ScopeRef,
		"featureSet", env.FeatureSet,
		"modelVersion", env.ModelVersion,
	)
}

func (p *SubscribingBaselineProvider) remove(scopeRef, featureSet string) {
	p.mu.Lock()
	delete(p.entries, cacheKey(scopeRef, featureSet))
	p.mu.Unlock()

	p.logger.V(vplogging.LogLevelDebug).Info("baseline evicted by invalidate envelope",
		"scopeRef", scopeRef,
		"featureSet", featureSet,
	)
}

// Size returns the current number of cached entries.
func (p *SubscribingBaselineProvider) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.entries)
}

func cacheKey(scopeRef, featureSet string) string {
	return scopeRef + "|" + featureSet
}

func waitOrCancel(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return fmt.Errorf("baseline subscriber wait cancelled: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// Ensure SubscribingBaselineProvider satisfies the historic
// BaselineProvider contract at compile time so the lateral movement
// detector can keep depending on the interface.
var _ BaselineProvider = (*SubscribingBaselineProvider)(nil)
