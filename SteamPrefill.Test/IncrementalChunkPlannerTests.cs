using SteamPrefill.Handlers;
using SteamPrefill.Models;
using Xunit;

namespace SteamPrefill.Test;

public sealed class IncrementalChunkPlannerTests
{
    [Fact]
    public void UpdatedManifestQueuesOnlyNewChunks()
    {
        var current = CreateManifest(2, ("same", 10), ("new", 20), ("new", 20));
        var baseline = new IncrementalDepotBaseline
        {
            ManifestId = 1,
            Chunks = new() { ["same"] = 10, ["removed"] = 30 }
        };

        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            current, baseline, IncrementalPrefillMode.Incremental);

        Assert.Collection(chunks, chunk => Assert.Equal("new", chunk.ChunkId));
        Assert.Equal(2, stats.TotalChunks);
        Assert.Equal(30, stats.TotalBytes);
        Assert.Equal(1, stats.QueuedChunks);
        Assert.Equal(20, stats.QueuedBytes);
        Assert.Equal(1, stats.SkippedChunks);
        Assert.Equal(10, stats.SkippedBytes);
    }

    [Theory]
    [InlineData(IncrementalPrefillMode.Full)]
    [InlineData(IncrementalPrefillMode.Repair)]
    public void FullModesQueueEveryDeduplicatedChunk(IncrementalPrefillMode mode)
    {
        var current = CreateManifest(2, ("same", 10), ("new", 20), ("same", 10));
        var baseline = new IncrementalDepotBaseline
        {
            ManifestId = 1,
            Chunks = new() { ["same"] = 10 }
        };

        var (chunks, stats) = IncrementalChunkPlanner.Plan(current, baseline, mode);

        Assert.Equal(new[] { "same", "new" }, chunks.Select(chunk => chunk.ChunkId));
        Assert.Equal(2, stats.QueuedChunks);
        Assert.Equal(30, stats.QueuedBytes);
    }

    [Fact]
    public void MissingBaselineQueuesEverything()
    {
        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            CreateManifest(2, ("one", 10), ("two", 20)), null, IncrementalPrefillMode.Incremental);

        Assert.Equal(2, chunks.Count);
        Assert.Equal(stats.TotalBytes, stats.QueuedBytes);
    }

    [Fact]
    public void CompletedCurrentManifestQueuesNothingEvenIfSuccessIndexWasNotCommitted()
    {
        var current = CreateManifest(2, ("one", 10), ("two", 20));
        var baseline = new IncrementalDepotBaseline
        {
            ManifestId = 2,
            Chunks = new() { ["one"] = 10, ["two"] = 20 }
        };

        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            current, baseline, IncrementalPrefillMode.Incremental);

        Assert.Empty(chunks);
        Assert.Equal(30, stats.SkippedBytes);
    }

    [Fact]
    public void DryRunCalculatesTheIncrementalDifference()
    {
        var baseline = new IncrementalDepotBaseline { ManifestId = 1, Chunks = new() { ["one"] = 10 } };
        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            CreateManifest(2, ("one", 10), ("two", 20)), baseline, IncrementalPrefillMode.DryRun);

        Assert.Single(chunks);
        Assert.Equal("two", chunks[0].ChunkId);
        Assert.Equal(10, stats.SkippedBytes);
    }

    [Fact]
    public void BootstrapQueuesNothingForAnExactlySuccessfulLegacyManifest()
    {
        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            CreateManifest(2, ("one", 10), ("two", 20)), null,
            IncrementalPrefillMode.Bootstrap, legacySuccess: true);

        Assert.Empty(chunks);
        Assert.Equal(30, stats.SkippedBytes);
    }

    [Fact]
    public void BootstrapReportsFullGapWhenCurrentManifestWasNotSuccessful()
    {
        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            CreateManifest(2, ("one", 10), ("two", 20)), null,
            IncrementalPrefillMode.Bootstrap, legacySuccess: false);

        Assert.Equal(2, chunks.Count);
        Assert.Equal(30, stats.QueuedBytes);
        Assert.Equal(0, stats.SkippedBytes);
    }

    [Fact]
    public void BootstrapUsesARecoveredHistoricalBaselineForTheDelta()
    {
        var baseline = new IncrementalDepotBaseline
        {
            ManifestId = 1,
            Chunks = new() { ["same"] = 10, ["removed"] = 30 }
        };
        var (chunks, stats) = IncrementalChunkPlanner.Plan(
            CreateManifest(2, ("same", 10), ("new", 20)), baseline,
            IncrementalPrefillMode.Bootstrap, legacySuccess: false);

        Assert.Collection(chunks, chunk => Assert.Equal("new", chunk.ChunkId));
        Assert.Equal(20, stats.QueuedBytes);
        Assert.Equal(10, stats.SkippedBytes);
    }

    private static Manifest CreateManifest(ulong id, params (string Id, uint Length)[] chunks)
    {
        var manifest = (Manifest)Activator.CreateInstance(typeof(Manifest), nonPublic: true)!;
        typeof(Manifest).GetProperty(nameof(Manifest.Id))!.SetValue(manifest, id);
        typeof(Manifest).GetProperty(nameof(Manifest.DepotId))!.SetValue(manifest, 100U);
        var file = (FileData)Activator.CreateInstance(typeof(FileData), nonPublic: true)!;
        file.Chunks.AddRange(chunks.Select(chunk => new ChunkData(chunk.Id, chunk.Length)));
        manifest.Files.Add(file);
        return manifest;
    }
}
