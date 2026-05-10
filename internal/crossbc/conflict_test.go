package crossbc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolver_NoSourcesPresent(t *testing.T) {
	r := NewResolver()

	result := r.Resolve(EnrichmentInput{})

	assert.Empty(t, result.Conflicts, "no inputs => no conflicts")
	assert.InDelta(t, 1.0, result.Confidence, 0.0001, "no penalties applied")
	assert.Empty(t, result.ResolvedAssetID)
}

func TestResolver_AegisWinsOverFlowSeekerForAssetID(t *testing.T) {
	r := NewResolver()

	result := r.Resolve(EnrichmentInput{
		FlowSeekerAssetID: "asset-fs",
		AegisAsset: &AegisAssetDetail{
			ID: "asset-aegis",
		},
	})

	assert.Equal(t, "asset-aegis", result.ResolvedAssetID, "Aegis must win for asset identity")
	assert.Len(t, result.Conflicts, 1)
	assert.Equal(t, "assetId", result.Conflicts[0].Field)
	assert.Equal(t, SourceAegis, result.Conflicts[0].Resolution)
	assert.InDelta(t, 0.95, result.Confidence, 0.0001, "one conflict => 0.05 penalty")
}

func TestResolver_AgreementOnAssetIDProducesNoConflict(t *testing.T) {
	r := NewResolver()

	result := r.Resolve(EnrichmentInput{
		FlowSeekerAssetID: "asset-1",
		AegisAsset: &AegisAssetDetail{
			ID: "asset-1",
		},
	})

	assert.Equal(t, "asset-1", result.ResolvedAssetID)
	assert.Empty(t, result.Conflicts, "matching values must not register a conflict")
	assert.InDelta(t, 1.0, result.Confidence, 0.0001)
}

func TestResolver_ZonePrecedence_AegisOverNetAtlasOverFlowSeeker(t *testing.T) {
	r := NewResolver()

	result := r.Resolve(EnrichmentInput{
		FlowSeekerZone: "zone-fs",
		NetAtlasZone:   "zone-na",
		AegisAsset:     &AegisAssetDetail{ID: "a", Zone: "zone-aegis"},
	})

	assert.Equal(t, "zone-aegis", result.ResolvedZone, "Aegis wins zone over NetAtlas and FlowSeeker")
	assert.Len(t, result.Conflicts, 2,
		"both NetAtlas and FlowSeeker conflict with Aegis on zone")
}

func TestResolver_ZoneFallsBackToNetAtlasWhenAegisSilent(t *testing.T) {
	r := NewResolver()

	result := r.Resolve(EnrichmentInput{
		FlowSeekerZone: "zone-fs",
		NetAtlasZone:   "zone-na",
	})

	assert.Equal(t, "zone-na", result.ResolvedZone)
	assert.Len(t, result.Conflicts, 1, "NetAtlas wins over FlowSeeker -> one conflict logged")
	assert.Equal(t, SourceNetAtlas, result.Conflicts[0].Resolution)
}

func TestResolver_DeviceFactsStaleReducesConfidence(t *testing.T) {
	r := NewResolver()

	result := r.Resolve(EnrichmentInput{
		NetSentinelDevice: &DeviceFactsResponse{
			DeviceIP:  "10.0.0.1",
			SysName:   "sw01",
			Freshness: FreshnessStale,
		},
	})

	assert.Equal(t, "sw01", result.ResolvedSysName)
	assert.Equal(t, FreshnessStale, result.DeviceFreshness)
	assert.InDelta(t, 0.9, result.Confidence, 0.0001, "stale facts should drop confidence by 0.1")
}

func TestResolver_ConfidenceFloorIs05(t *testing.T) {
	r := NewResolver()

	// 11 conflicts on zone: each pairwise mismatch counts. We force conflicts
	// by stacking incompatible zones — but the resolver only emits one
	// conflict per non-winning candidate, so we pile them up via repeated
	// Resolve calls aggregating manually for the floor check.
	heavy := EnrichmentResult{Confidence: 1.0}
	for i := 0; i < 50; i++ {
		heavy.Conflicts = append(heavy.Conflicts, Conflict{Field: "x"})
	}

	heavy.DeviceFreshness = FreshnessStale
	r.applyConfidenceDampening(&heavy)

	assert.InDelta(t, 0.5, heavy.Confidence, 0.0001, "confidence must not drop below 0.5")
}

func TestResolver_ConflictCodesShape(t *testing.T) {
	result := EnrichmentResult{
		Conflicts: []Conflict{
			{Field: "assetId", Resolution: SourceAegis},
			{Field: "zone", Resolution: SourceNetAtlas},
		},
	}

	codes := result.ConflictCodes()

	assert.Equal(t, []string{"assetId:aegis", "zone:netatlas"}, codes)
}
