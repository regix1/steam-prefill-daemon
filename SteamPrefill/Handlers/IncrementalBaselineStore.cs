namespace SteamPrefill.Handlers
{
    /// <summary>
    /// Persists the chunk inventory of the last successfully completed manifest for each depot.
    /// This is deliberately stored under Config rather than the disposable manifest cache.
    /// </summary>
    public sealed class IncrementalBaselineStore
    {
        private readonly object _gate = new();
        private readonly string _root;
        private readonly string _cacheGeneration;
        private readonly Action<string, string> _replace;

        public IncrementalBaselineStore(string path = null, string cacheGeneration = null,
            Action<string, string> replace = null)
        {
            _root = path ?? AppConfig.IncrementalStatePath;
            _cacheGeneration = cacheGeneration ?? AppConfig.CacheGeneration;
            _replace = replace ?? ((source, destination) => File.Move(source, destination, true));
        }

        public IncrementalDepotBaseline Get(uint depotId)
        {
            lock (_gate)
            {
                if (!GenerationMatches()) return null;
                var path = DepotPath(depotId);
                Manifest manifest;
                try
                {
                    manifest = Manifest.LoadFromFile(path);
                }
                catch (Exception exception) when (exception is IOException or ProtoException)
                {
                    // A partial or damaged baseline must never prevent a safe full-prefill fallback.
                    File.Delete(path);
                    return null;
                }
                if (manifest == null) return null;
                if (manifest.DepotId != depotId)
                {
                    File.Delete(path);
                    return null;
                }
                return new IncrementalDepotBaseline
                {
                    ManifestId = manifest.Id,
                    Chunks = manifest.Files.SelectMany(file => file.Chunks)
                        .GroupBy(chunk => chunk.ChunkId, StringComparer.Ordinal)
                        .ToDictionary(group => group.Key, group => group.First().CompressedLength,
                            StringComparer.Ordinal)
                };
            }
        }

        public void Commit(IEnumerable<Manifest> manifests)
        {
            lock (_gate)
            {
                EnsureGenerationForWrite();
                foreach (var manifest in manifests)
                {
                    manifest.SaveToFile(DepotPath(manifest.DepotId), _replace);
                }
            }
        }

        public int Clear()
        {
            lock (_gate)
            {
                var count = Directory.Exists(DepotsPath)
                    ? Directory.EnumerateFiles(DepotsPath, "*.bin").Count()
                    : 0;
                if (Directory.Exists(_root)) Directory.Delete(_root, true);
                return count;
            }
        }

        private string DepotsPath => Path.Combine(_root, "depots");
        private string GenerationPath => Path.Combine(_root, "generation.txt");
        private string DepotPath(uint depotId) => Path.Combine(DepotsPath, $"{depotId}.bin");

        private bool GenerationMatches()
        {
            try
            {
                return String.Equals(File.ReadAllText(GenerationPath).Trim(), _cacheGeneration,
                    StringComparison.Ordinal);
            }
            catch (IOException)
            {
                return false;
            }
        }

        private void EnsureGenerationForWrite()
        {
            if (GenerationMatches())
            {
                Directory.CreateDirectory(DepotsPath);
                return;
            }
            if (Directory.Exists(_root)) Directory.Delete(_root, true);
            Directory.CreateDirectory(DepotsPath);
            AtomicWriteText(GenerationPath, _cacheGeneration + Environment.NewLine);
        }

        private void AtomicWriteText(string path, string value)
        {
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream))
                {
                    writer.Write(value);
                    writer.Flush();
                    stream.Flush(true);
                }
                File.Move(temporary, path, true);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }

    public static class IncrementalChunkPlanner
    {
        public static (List<ChunkData> Chunks, IncrementalQueueStats Stats) Plan(
            Manifest current, IncrementalDepotBaseline baseline, IncrementalPrefillMode mode,
            bool legacySuccess = false)
        {
            var all = current.Files.SelectMany(file => file.Chunks)
                .DistinctBy(chunk => chunk.ChunkId)
                .ToList();
            var totalBytes = all.Sum(chunk => (long)chunk.CompressedLength);
            var useBaseline = mode is IncrementalPrefillMode.Incremental or IncrementalPrefillMode.DryRun
                || mode == IncrementalPrefillMode.Bootstrap && baseline != null;
            var bootstrapCurrent = mode == IncrementalPrefillMode.Bootstrap && legacySuccess;
            var queued = bootstrapCurrent
                ? new List<ChunkData>()
                : useBaseline && baseline != null
                ? all.Where(chunk => !baseline.Chunks.ContainsKey(chunk.ChunkId)).ToList()
                : all;
            var queuedBytes = queued.Sum(chunk => (long)chunk.CompressedLength);
            return (queued, new IncrementalQueueStats(all.Count, totalBytes, queued.Count, queuedBytes));
        }
    }
}
