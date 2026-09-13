using LancachePrefill.Common;
using SteamKit2;
using SteamPrefill.Handlers;
using SteamPrefill.Models;
using Xunit;

namespace SteamPrefill.Test;

public sealed class CacheCommitTests
{
    [Theory]
    [InlineData("terminal")]
    [InlineData("commit")]
    [InlineData("throw")]
    public async Task DepotCommitSharesAppTerminalBoundary(string ordering)
    {
        var directory = Path.Combine(Path.GetTempPath(), "steam-commit-order-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "success.json");
        var progress = new RunProgress("operation", "instance", new RunOptions { AppIds = new[] { "100" }, MaxConcurrency = 1 });
        var item = new RunItemSnapshot { AppId = "100", Name = "Game", State = "completed", Result = "success", TotalBytes = 3, BytesTransferred = 3 };
        var first = new DepotInfo(new KeyValue("101"), 100) { ManifestId = 1 };
        var second = new DepotInfo(new KeyValue("102"), 100) { ManifestId = 2 };
        var replaced = 0;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        var failure = new IOException("Replacement failed.");
        var handler = new DepotHandler(null!, null!, null!, path, (source, destination) =>
        {
            entered.TrySetResult();
            if (ordering == "throw") throw failure;
            if (ordering == "commit" && !release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException();
            File.Move(source, destination, true);
            Interlocked.Increment(ref replaced);
        });
        try
        {
            var before = progress.Snapshot;
            if (ordering == "terminal")
            {
                Assert.True(progress.TryChooseTerminal("cancelled"));
                var terminal = progress.Snapshot;
                Assert.False(handler.MarkDownloadAsSuccessful(new() { first, second }, progress, item));
                Assert.False(entered.Task.IsCompleted);
                Assert.Equal(terminal, progress.Snapshot);
                Assert.False(handler.AppIsUpToDate(new() { first, second }));
                Assert.Empty(Directory.GetFiles(directory));
            }
            else if (ordering == "throw")
            {
                Assert.Same(failure, Assert.Throws<IOException>(() => handler.MarkDownloadAsSuccessful(new() { first, second }, progress, item)));
                Assert.Equal(before, progress.Snapshot);
                Assert.False(handler.AppIsUpToDate(new() { first, second }));
                Assert.Empty(Directory.GetFiles(directory));
            }
            else
            {
                var committing = Task.Run(() => handler.MarkDownloadAsSuccessful(new() { first, second }, progress, item));
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                var cancelling = Task.Run(() => progress.TryChooseTerminal("cancelled"));
                release.Set();
                Assert.True(await committing.WaitAsync(TimeSpan.FromSeconds(5)));
                Assert.True(await cancelling.WaitAsync(TimeSpan.FromSeconds(5)));
                await progress.CompleteAsync();
                Assert.Equal(1, replaced);
                Assert.True(handler.AppIsUpToDate(new() { first, second }));
                Assert.True(new DepotHandler(null!, null!, null!, path).AppIsUpToDate(new() { first, second }));
                Assert.Equal("cancelled", progress.Snapshot.State);
                Assert.Equal(1, progress.Snapshot.CompletedApps);
                Assert.Equal(3, progress.Snapshot.BytesTransferred);
                Assert.Equal(before.Sequence + 2, progress.Snapshot.Sequence);
                Assert.Single(Directory.GetFiles(directory));
            }
        }
        finally
        {
            release.Set();
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task ConcurrentDepotCommitsMergeAndFailedReplacementPreservesBothCopies()
    {
        var directory = Path.Combine(Path.GetTempPath(), "steam-commits-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "success.json");
        var fail = false;
        var handler = new DepotHandler(null!, null!, null!, path, (source, destination) =>
        {
            if (fail) throw new IOException("Replacement failed.");
            File.Move(source, destination, true);
        });
        var first = new DepotInfo(new KeyValue("101"), 100) { ManifestId = 1 };
        var second = new DepotInfo(new KeyValue("201"), 200) { ManifestId = 2 };
        var third = new DepotInfo(new KeyValue("301"), 300) { ManifestId = 3 };
        try
        {
            await Task.WhenAll(Task.Run(() => handler.MarkDownloadAsSuccessful(new() { first })),
                Task.Run(() => handler.MarkDownloadAsSuccessful(new() { second })));
            Assert.True(handler.AppIsUpToDate(new() { first, second }));
            var persisted = new DepotHandler(null!, null!, null!, path);
            Assert.True(persisted.AppIsUpToDate(new() { first, second }));
            var previous = File.ReadAllBytes(path);
            fail = true;
            Assert.Throws<IOException>(() => handler.MarkDownloadAsSuccessful(new() { third }));
            Assert.Equal(previous, File.ReadAllBytes(path));
            Assert.False(handler.AppIsUpToDate(new() { third }));
            Assert.True(handler.AppIsUpToDate(new() { first, second }));
            Assert.Single(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void ManifestReplacementFailureKeepsThePreviousManifestReadable()
    {
        var directory = Path.Combine(Path.GetTempPath(), "steam-manifest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "manifest.bin");
        try
        {
            var manifest = (Manifest)Activator.CreateInstance(typeof(Manifest), nonPublic: true)!;
            typeof(Manifest).GetProperty(nameof(Manifest.Id))!.SetValue(manifest, 1UL);
            manifest.SaveToFile(path);
            var original = File.ReadAllBytes(path);
            typeof(Manifest).GetProperty(nameof(Manifest.Id))!.SetValue(manifest, 2UL);
            Assert.Throws<IOException>(() => manifest.SaveToFile(path, (_, _) => throw new IOException("Replacement failed.")));
            Assert.Equal(original, File.ReadAllBytes(path));
            Assert.Equal(1UL, Manifest.LoadFromFile(path).Id);
            Assert.Single(Directory.GetFiles(directory));
        }
        finally { Directory.Delete(directory, true); }
    }
}
