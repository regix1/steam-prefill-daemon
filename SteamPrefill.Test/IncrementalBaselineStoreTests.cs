using SteamPrefill.Handlers;
using SteamPrefill.Models;
using Xunit;

namespace SteamPrefill.Test;

public sealed class IncrementalBaselineStoreTests
{
    [Fact]
    public void CommitIsPersistedAndGenerationChangeInvalidatesIt()
    {
        var directory = TemporaryDirectory();
        var path = Path.Combine(directory, "state");
        try
        {
            var store = new IncrementalBaselineStore(path, "generation-one");
            store.Commit(new[] { CreateManifest(100, 2, ("one", 10), ("two", 20)) });

            var loaded = new IncrementalBaselineStore(path, "generation-one").Get(100);
            Assert.NotNull(loaded);
            Assert.Equal(2UL, loaded!.ManifestId);
            Assert.Equal(2, loaded.Chunks.Count);
            Assert.Null(new IncrementalBaselineStore(path, "generation-two").Get(100));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void FailedAtomicReplacementPreservesPreviousBaseline()
    {
        var directory = TemporaryDirectory();
        var path = Path.Combine(directory, "state");
        try
        {
            var original = new IncrementalBaselineStore(path, "one");
            original.Commit(new[] { CreateManifest(100, 1, ("old", 10)) });
            var depotPath = Path.Combine(path, "depots", "100.bin");
            var bytes = File.ReadAllBytes(depotPath);
            var failing = new IncrementalBaselineStore(path, "one", (_, _) => throw new IOException("failed"));

            Assert.Throws<IOException>(() => failing.Commit(new[] { CreateManifest(100, 2, ("new", 20)) }));
            Assert.Equal(bytes, File.ReadAllBytes(depotPath));
            Assert.Equal(1UL, new IncrementalBaselineStore(path, "one").Get(100)!.ManifestId);
            Assert.Equal(2, Directory.GetFiles(path, "*", SearchOption.AllDirectories).Length);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void ClearRemovesPersistentState()
    {
        var directory = TemporaryDirectory();
        var path = Path.Combine(directory, "state");
        try
        {
            var store = new IncrementalBaselineStore(path, "one");
            store.Commit(new[] { CreateManifest(100, 1, ("old", 10)) });
            Assert.Equal(1, store.Clear());
            Assert.False(Directory.Exists(path));
            Assert.Null(store.Get(100));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void CorruptBaselineIsRemovedAndTreatedAsMissing()
    {
        var directory = TemporaryDirectory();
        var path = Path.Combine(directory, "state");
        try
        {
            var store = new IncrementalBaselineStore(path, "one");
            store.Commit(new[] { CreateManifest(100, 1, ("old", 10)) });
            var depotPath = Path.Combine(path, "depots", "100.bin");
            File.WriteAllText(depotPath, "not a protobuf manifest");

            Assert.Null(store.Get(100));
            Assert.False(File.Exists(depotPath));
        }
        finally { Directory.Delete(directory, true); }
    }

    [Fact]
    public void UpdatingOneDepotDoesNotRewriteAnotherDepot()
    {
        var directory = TemporaryDirectory();
        var path = Path.Combine(directory, "state");
        try
        {
            var store = new IncrementalBaselineStore(path, "one");
            store.Commit(new[]
            {
                CreateManifest(100, 1, ("old", 10)),
                CreateManifest(200, 1, ("stable", 20))
            });
            var stablePath = Path.Combine(path, "depots", "200.bin");
            var bytes = File.ReadAllBytes(stablePath);
            var modified = File.GetLastWriteTimeUtc(stablePath);

            store.Commit(new[] { CreateManifest(100, 2, ("new", 30)) });

            Assert.Equal(bytes, File.ReadAllBytes(stablePath));
            Assert.Equal(modified, File.GetLastWriteTimeUtc(stablePath));
            Assert.Equal(2UL, store.Get(100)!.ManifestId);
            Assert.Equal(1UL, store.Get(200)!.ManifestId);
        }
        finally { Directory.Delete(directory, true); }
    }

    private static string TemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "steam-incremental-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static Manifest CreateManifest(uint depotId, ulong manifestId, params (string Id, uint Length)[] chunks)
    {
        var manifest = (Manifest)Activator.CreateInstance(typeof(Manifest), nonPublic: true)!;
        typeof(Manifest).GetProperty(nameof(Manifest.Id))!.SetValue(manifest, manifestId);
        typeof(Manifest).GetProperty(nameof(Manifest.DepotId))!.SetValue(manifest, depotId);
        var file = (FileData)Activator.CreateInstance(typeof(FileData), nonPublic: true)!;
        file.Chunks.AddRange(chunks.Select(chunk => new ChunkData(chunk.Id, chunk.Length)));
        manifest.Files.Add(file);
        return manifest;
    }
}
