package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"vigilprotector.io/vp-lib/baselines"
)

type fakeSubscription struct {
	mu        sync.Mutex
	envelopes []baselines.Envelope
	pos       int
	acked     []string
}

func (f *fakeSubscription) Next(_ context.Context) (baselines.Envelope, baselines.Ack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.pos >= len(f.envelopes) {
		return baselines.Envelope{}, nil, baselines.ErrSubscriptionClosed
	}

	env := f.envelopes[f.pos]
	f.pos++

	ack := func(_ context.Context) error {
		f.mu.Lock()
		defer f.mu.Unlock()

		f.acked = append(f.acked, env.BaselineID)

		return nil
	}

	return env, ack, nil
}

func (f *fakeSubscription) Close() error { return nil }

func makeEnv(scope, feature, baselineID string) baselines.Envelope {
	now := time.Now().UTC()

	return baselines.Envelope{
		SchemaVersion: baselines.SchemaVersion,
		BaselineID:    baselineID,
		BaselineType:  "stratosage.feature_baseline",
		SourceContext: "stratosage",
		ScopeRef:      scope,
		FeatureSet:    feature,
		ModelVersion:  "1.0",
		Action:        baselines.ActionPublished,
		TrainedAt:     now,
		ValidFrom:     now,
		SummaryStats:  map[string]float64{"avg": 1.5},
		Confidence:    0.8,
		OccurredAt:    now,
		CorrelationID: "corr-" + baselineID,
	}
}

func TestSubscribingBaselineProvider_PublishedEnvelopesPopulateMap(t *testing.T) {
	t.Parallel()

	sub := &fakeSubscription{
		envelopes: []baselines.Envelope{
			makeEnv("asset:a", "lateral_movement", "bl-1"),
			makeEnv("asset:b", "exfiltration", "bl-2"),
		},
	}

	provider, err := NewSubscribingBaselineProvider(SubscribingBaselineProviderConfig{
		Subscription: sub,
		Logger:       logr.Discard(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	require.NoError(t, provider.Run(ctx))

	got, err := provider.GetBaseline(t.Context(), "asset:a", "lateral_movement")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "bl-1", got.ID)
	assert.InDelta(t, 1.5, got.Stats["avg"], 0.0001)

	assert.Equal(t, 2, provider.Size())
}

func TestSubscribingBaselineProvider_InvalidatedEnvelopeEvicts(t *testing.T) {
	t.Parallel()

	published := makeEnv("asset:a", "lateral_movement", "bl-1")
	invalidated := makeEnv("asset:a", "lateral_movement", "bl-1")
	invalidated.Action = baselines.ActionInvalidated

	sub := &fakeSubscription{envelopes: []baselines.Envelope{published, invalidated}}
	provider, _ := NewSubscribingBaselineProvider(SubscribingBaselineProviderConfig{
		Subscription: sub,
		Logger:       logr.Discard(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	require.NoError(t, provider.Run(ctx))

	got, err := provider.GetBaseline(t.Context(), "asset:a", "lateral_movement")
	require.NoError(t, err)
	assert.Nil(t, got, "invalidated envelope must evict the entry")
}

func TestSubscribingBaselineProvider_GetBaselineMissReturnsNil(t *testing.T) {
	t.Parallel()

	sub := &fakeSubscription{}
	provider, _ := NewSubscribingBaselineProvider(SubscribingBaselineProviderConfig{
		Subscription: sub,
		Logger:       logr.Discard(),
	})

	got, err := provider.GetBaseline(t.Context(), "asset:nope", "lateral_movement")

	require.NoError(t, err)
	assert.Nil(t, got, "miss must be nil, nil (matching historic BaselineProvider contract)")
}

func TestSubscribingBaselineProvider_GetBaselinesForScopeFilters(t *testing.T) {
	t.Parallel()

	sub := &fakeSubscription{
		envelopes: []baselines.Envelope{
			makeEnv("asset:a", "lateral_movement", "bl-1"),
			makeEnv("asset:a", "exfiltration", "bl-2"),
			makeEnv("asset:b", "lateral_movement", "bl-3"),
		},
	}
	provider, _ := NewSubscribingBaselineProvider(SubscribingBaselineProviderConfig{
		Subscription: sub,
		Logger:       logr.Discard(),
	})

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	require.NoError(t, provider.Run(ctx))

	got, err := provider.GetBaselinesForScope(t.Context(), "asset:a")

	require.NoError(t, err)
	assert.Len(t, got, 2)

	ids := []string{got[0].ID, got[1].ID}
	assert.ElementsMatch(t, []string{"bl-1", "bl-2"}, ids)
}

func TestSubscribingBaselineProvider_RejectsNilSubscription(t *testing.T) {
	t.Parallel()

	_, err := NewSubscribingBaselineProvider(SubscribingBaselineProviderConfig{})

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingSubscription))
}
