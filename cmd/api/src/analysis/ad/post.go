package ad

import (
	"context"

	"github.com/specterops/bloodhound/analysis"
	adAnalysis "github.com/specterops/bloodhound/analysis/ad"
	"github.com/specterops/bloodhound/dawgs/graph"
	"github.com/specterops/bloodhound/graphschema/ad"
	"github.com/specterops/bloodhound/graphschema/azure"
)

func Post(ctx context.Context, db graph.Database, adcsEnabled, citrixEnabled, ntlmEnabled bool, compositionCounter *analysis.CompositionCounter) (*analysis.AtomicPostProcessingStats, error) {
	aggregateStats := analysis.NewAtomicPostProcessingStats()
	if stats, err := analysis.DeleteTransitEdges(ctx, db, graph.Kinds{ad.Entity, azure.Entity}, adAnalysis.PostProcessedRelationships()...); err != nil {
		return &aggregateStats, err
	} else if groupExpansions, err := adAnalysis.ExpandAllRDPLocalGroups(ctx, db); err != nil {
		return &aggregateStats, err
	} else if dcSyncStats, err := adAnalysis.PostDCSync(ctx, db, groupExpansions); err != nil {
		return &aggregateStats, err
	} else if syncLAPSStats, err := adAnalysis.PostSyncLAPSPassword(ctx, db, groupExpansions); err != nil {
		return &aggregateStats, err
	} else if hasTrustKeyStats, err := adAnalysis.PostHasTrustKeys(ctx, db); err != nil {
		return &aggregateStats, err
	} else if localGroupStats, err := adAnalysis.PostLocalGroups(ctx, db, groupExpansions, false, citrixEnabled); err != nil {
		return &aggregateStats, err
	} else if adcsStats, adcsCache, err := adAnalysis.PostADCS(ctx, db, groupExpansions, adcsEnabled); err != nil {
		return &aggregateStats, err
	} else if ownsStats, err := adAnalysis.PostOwnsAndWriteOwner(ctx, db, groupExpansions); err != nil {
		return &aggregateStats, err
	} else if ntlmStats, err := adAnalysis.PostNTLM(ctx, db, groupExpansions, adcsCache, ntlmEnabled, compositionCounter); err != nil {
		return &aggregateStats, err
	} else {
		aggregateStats.Merge(stats)
		aggregateStats.Merge(syncLAPSStats)
		aggregateStats.Merge(hasTrustKeyStats)
		aggregateStats.Merge(dcSyncStats)
		aggregateStats.Merge(localGroupStats)
		aggregateStats.Merge(adcsStats)
		aggregateStats.Merge(ownsStats)
		aggregateStats.Merge(ntlmStats)
		return &aggregateStats, nil
	}
}
