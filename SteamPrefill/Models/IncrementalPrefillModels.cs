namespace SteamPrefill.Models
{
    public enum IncrementalPrefillMode
    {
        Incremental,
        Full,
        Repair,
        DryRun,
        Bootstrap
    }

    public sealed class IncrementalDepotBaseline
    {
        public ulong ManifestId { get; set; }
        public Dictionary<string, uint> Chunks { get; set; } = new(StringComparer.Ordinal);
    }

    public readonly record struct IncrementalQueueStats(
        int TotalChunks,
        long TotalBytes,
        int QueuedChunks,
        long QueuedBytes)
    {
        public int SkippedChunks => TotalChunks - QueuedChunks;
        public long SkippedBytes => TotalBytes - QueuedBytes;
    }
}
