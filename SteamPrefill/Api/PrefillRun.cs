using LancachePrefill.Common;

#nullable enable

namespace SteamPrefill.Api;

internal sealed class PrefillRun
{
    internal static readonly AsyncLocal<PrefillRun?> Current = new();
    private readonly ConcurrentBag<Task> _pending = new();
    private readonly ConcurrentBag<IDisposable> _leases = new();
    private readonly ConcurrentDictionary<string, long> _bytes = new(StringComparer.Ordinal);
    internal RunOptions Options { get; }
    internal bool CacheSnapshot { get; }
    internal RunProgress Progress { get; }
    internal RequestBudget Budget { get; }
    internal ItemClaims Claims { get; }
    internal ConcurrentDictionary<string, List<DepotManifestUpdateInfo>> Depots { get; } = new(StringComparer.Ordinal);
    internal DownloadArguments Arguments { get; }
    internal string OperationId => Progress.Snapshot.OperationId;

    internal PrefillRun(RunOptions options, RunProgress progress, RequestBudget budget, ItemClaims claims,
        bool cacheSnapshot = false)
    {
        Options = options;
        CacheSnapshot = cacheSnapshot;
        Progress = progress;
        Budget = budget;
        Claims = claims;
        Arguments = new DownloadArguments
        {
            Force = options.Force,
            MaxConcurrentRequests = options.MaxConcurrency,
            OperatingSystems = options.OperatingSystems.Select(OperatingSystem.FromValue).ToList()
        };
    }

    internal void Track(Task task) => _pending.Add(task);
    internal void Hold(IDisposable lease) => _leases.Add(lease);
    internal long Bytes(string appId) => _bytes.GetValueOrDefault(appId);
    internal void AddBytes(uint appId, int count) => _bytes.AddOrUpdate(appId.ToString(System.Globalization.CultureInfo.InvariantCulture), count, (_, previous) => previous + count);

    internal async Task ReleaseAsync()
    {
        try
        {
            while (!_pending.IsEmpty)
            {
                var pending = new List<Task>();
                while (_pending.TryTake(out var task)) pending.Add(task);
                try { await Task.WhenAll(pending); }
                catch (OperationCanceledException) { }
                catch (Exception exception) { FileLogger.LogException("Pending Steam request failed", exception); }
            }
        }
        finally
        {
            while (_leases.TryTake(out var lease)) lease.Dispose();
        }
    }

    internal async Task CompleteAsync()
    {
        await ReleaseAsync();
        await Progress.CompleteAsync(_bytes.Values.Sum(), _bytes);
    }
}
