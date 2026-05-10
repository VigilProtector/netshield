package crossbc

import (
	"fmt"
	"strings"
)

// EnrichmentInput collects the per-source view of one detection's flow context
// before NH-CC-003 conflict resolution runs. Every field is optional — Resolver
// gracefully handles partial views (e.g. Aegis silent because the asset is new,
// NetAtlas absent in single-zone deployments). Empty strings are treated as
// "this source had nothing to say" rather than a real disagreement.
type EnrichmentInput struct {
	FlowSeekerAssetID string
	FlowSeekerZone    string

	AegisAsset *AegisAssetDetail

	NetSentinelDevice *DeviceFactsResponse

	NetAtlasZone string
}

// EnrichmentResult is the post-resolution view consumers use when emitting the
// downstream Finding. ResolvedAssetID etc. always reflect the winner under the
// declared precedence (see Resolver), Conflicts records every disagreement
// encountered and Confidence is dampened (0.5..1.0) when conflicts or stale
// sources reduce trust.
type EnrichmentResult struct {
	ResolvedAssetID     string
	ResolvedZone        string
	ResolvedCriticality string
	ResolvedSysName     string
	DeviceFreshness     string
	Conflicts           []Conflict
	Confidence          float64
}

// Conflict is a single disagreement between two sources for one logical field.
// SourceA/B and ValueA/B are kept stable so a worklist UI can display the raw
// pair the resolver decided between, and Resolution names the winning source.
type Conflict struct {
	Field      string
	SourceA    string
	ValueA     string
	SourceB    string
	ValueB     string
	Resolution string
}

// String renders a Conflict in a stable "field:winner(loser)" form suitable
// for Attribute/log payloads. It is intentionally compact — full details
// remain on the struct itself for structured consumers.
func (c Conflict) String() string {
	return fmt.Sprintf("%s:%s(over=%s)", c.Field, c.Resolution, c.loser())
}

func (c Conflict) loser() string {
	if c.SourceA == c.Resolution {
		return c.SourceB
	}

	return c.SourceA
}

// Source identifiers used in Conflict payloads. Kept as constants so callers
// don't drift on capitalisation.
const (
	SourceFlowSeeker  = "flowseeker"
	SourceAegis       = "aegis"
	SourceNetSentinel = "netsentinel"
	SourceNetAtlas    = "netatlas"
)

// Resolver applies an explicit, documented precedence order across the
// cross-BC enrichment sources to satisfy NH-CC-003: contradictions must not
// be silently resolved by "whichever ran last", every disagreement must be
// attributable, and the consumer needs a single Confidence number to gate
// downstream actions.
//
// Precedence:
//   - Asset identity:    Aegis  > FlowSeeker
//   - Zone:              Aegis  > NetAtlas  > FlowSeeker
//   - Criticality:       Aegis only
//   - Device facts:      NetSentinel only, freshness-gated
//
// Confidence dampening:
//   - 1.0 base
//   - −0.05 per Conflict (capped at 0.5)
//   - extra −0.1 if NetSentinel freshness == stale
type Resolver struct{}

// NewResolver returns a Resolver. Kept as a constructor (rather than a
// package-level singleton) so tests can swap implementations later without
// touching every call site.
func NewResolver() *Resolver { return &Resolver{} }

// Resolve produces an EnrichmentResult for input. It is side-effect-free:
// the input is not mutated, and the returned conflicts slice is independent.
func (r *Resolver) Resolve(input EnrichmentInput) EnrichmentResult {
	result := EnrichmentResult{Confidence: 1.0}

	r.resolveAssetID(input, &result)
	r.resolveZone(input, &result)
	r.resolveCriticality(input, &result)
	r.resolveDeviceFacts(input, &result)

	r.applyConfidenceDampening(&result)

	return result
}

func (r *Resolver) resolveAssetID(input EnrichmentInput, result *EnrichmentResult) {
	switch {
	case input.AegisAsset != nil && input.AegisAsset.ID != "":
		result.ResolvedAssetID = input.AegisAsset.ID

		if input.FlowSeekerAssetID != "" && input.FlowSeekerAssetID != input.AegisAsset.ID {
			result.Conflicts = append(result.Conflicts, Conflict{
				Field:      "assetId",
				SourceA:    SourceFlowSeeker,
				ValueA:     input.FlowSeekerAssetID,
				SourceB:    SourceAegis,
				ValueB:     input.AegisAsset.ID,
				Resolution: SourceAegis,
			})
		}
	default:
		result.ResolvedAssetID = input.FlowSeekerAssetID
	}
}

func (r *Resolver) resolveZone(input EnrichmentInput, result *EnrichmentResult) {
	candidates := []struct {
		source string
		value  string
	}{
		{SourceAegis, ""},
		{SourceNetAtlas, input.NetAtlasZone},
		{SourceFlowSeeker, input.FlowSeekerZone},
	}

	if input.AegisAsset != nil {
		candidates[0].value = input.AegisAsset.Zone
	}

	winner := struct {
		source string
		value  string
	}{}

	for _, candidate := range candidates {
		if candidate.value == "" {
			continue
		}

		if winner.value == "" {
			winner = candidate

			continue
		}

		if candidate.value != winner.value {
			result.Conflicts = append(result.Conflicts, Conflict{
				Field:      "zone",
				SourceA:    candidate.source,
				ValueA:     candidate.value,
				SourceB:    winner.source,
				ValueB:     winner.value,
				Resolution: winner.source,
			})
		}
	}

	result.ResolvedZone = winner.value
}

func (r *Resolver) resolveCriticality(input EnrichmentInput, result *EnrichmentResult) {
	if input.AegisAsset == nil {
		return
	}

	result.ResolvedCriticality = input.AegisAsset.Criticality
}

func (r *Resolver) resolveDeviceFacts(input EnrichmentInput, result *EnrichmentResult) {
	if input.NetSentinelDevice == nil {
		return
	}

	result.ResolvedSysName = input.NetSentinelDevice.SysName
	result.DeviceFreshness = strings.ToLower(input.NetSentinelDevice.Freshness)
}

func (r *Resolver) applyConfidenceDampening(result *EnrichmentResult) {
	const (
		conflictPenalty = 0.05
		stalePenalty    = 0.1
		minConfidence   = 0.5
	)

	result.Confidence -= float64(len(result.Conflicts)) * conflictPenalty

	if result.DeviceFreshness == FreshnessStale {
		result.Confidence -= stalePenalty
	}

	if result.Confidence < minConfidence {
		result.Confidence = minConfidence
	}
}

// ConflictCodes returns the stable per-Conflict identifier slice
// ("field:winner") used as a compact attribute payload on the eventual
// downstream Finding. Order matches the order the Conflicts were emitted.
func (r EnrichmentResult) ConflictCodes() []string {
	codes := make([]string, 0, len(r.Conflicts))

	for _, c := range r.Conflicts {
		codes = append(codes, c.Field+":"+c.Resolution)
	}

	return codes
}
