using Serializer = ProtoBuf.Serializer;

namespace SteamPrefill.Models
{
    [ProtoContract]
    public sealed class Manifest
    {
        [ProtoMember(1)]
        public List<FileData> Files { get; private set; }

        [ProtoMember(2)]
        public ulong Id { get; private set; }

        [ProtoMember(4)]
        public uint DepotId { get; private set; }

        // Used for deserialization
        private Manifest()
        {
            Files = new List<FileData>();
        }

        public Manifest(DepotManifest sourceManifest, DepotInfo depotInfo) : this()
        {
            Files = sourceManifest.Files.Select(e => new FileData(e)).ToList();
            Id = depotInfo.ManifestId.Value;
            DepotId = depotInfo.DepotId;
        }

        public static Manifest LoadFromFile(string filename)
        {
            if (!File.Exists(filename))
            {
                return null;
            }
            using var fs = File.Open(filename, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            return Serializer.Deserialize<Manifest>(fs);
        }

        public void SaveToFile(string filename, Action<string, string> replace = null)
        {
            var temporary = filename + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    Serializer.Serialize(stream, this);
                    stream.Flush(true);
                }
                if (replace == null) File.Move(temporary, filename, true);
                else replace(temporary, filename);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }

    [ProtoContract]
    public sealed class FileData
    {
        /// <summary>
        /// Gets the chunks that this file is composed of.
        /// </summary>
        [ProtoMember(1)]
        public List<ChunkData> Chunks { get; }

        // Used for deserialization
        private FileData()
        {
            Chunks = new List<ChunkData>();
        }

        public FileData(DepotManifest.FileData sourceData) : this()
        {
            Chunks = sourceData.Chunks
                               .Select(e => new ChunkData(e))
                               .ToList();
        }
    }

    [ProtoContract(SkipConstructor = true)]
    public readonly struct ChunkData
    {
        /// <summary>
        /// SHA-1 hash of the chunk, used as its Id.
        /// </summary>
        [ProtoMember(1)]
        public readonly string ChunkId;

        /// <summary>
        /// Steam compresses every chunk individually, this is the resulting compressed size in bytes
        /// </summary>
        [ProtoMember(2)]
        public readonly uint CompressedLength;

        public ChunkData(DepotManifest.ChunkData sourceChunk)
        {
            ChunkId = HexMate.Convert.ToHexString(sourceChunk.ChunkID, HexFormattingOptions.Lowercase);
            CompressedLength = sourceChunk.CompressedLength;
        }

        public override string ToString()
        {
            return $"{ChunkId} - {CompressedLength}";
        }
    }
}
