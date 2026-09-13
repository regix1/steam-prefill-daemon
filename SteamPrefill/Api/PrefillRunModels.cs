#nullable enable

namespace SteamPrefill.Api
{

    internal sealed record PrefillStart
    {
        public bool Success { get; init; } = true;
        public required string RunId { get; init; }
        public required string DaemonInstanceId { get; init; }
        public string State { get; init; } = "started";
        public LancachePrefill.Common.RunSnapshot? Operation { get; init; }
    }

    internal sealed class AutoLoginChallengeData
    {
        public required string ChallengeId { get; init; }
        public required System.Security.Cryptography.ECParameters ServerPrivateKey { get; init; }
        public required byte[] ServerPublicKey { get; init; }
        public required DateTime ExpiresAt { get; init; }
        public required long Generation { get; init; }
    }

    internal sealed record PrefillPage
    {
        public required LancachePrefill.Common.RunSnapshot Operation { get; init; }
        public required LancachePrefill.Common.RunOptions Options { get; init; }
        public bool SelectionResolved { get; init; }
        public int TotalItems { get; init; }
        public int? NextOffset { get; init; }
        public required IReadOnlyList<PrefillItem> Items { get; init; }
    }

    internal sealed record PrefillItem
    {
        public required string AppId { get; init; }
        public string? Name { get; init; }
        public string State { get; init; } = "pending";
        public string? Result { get; init; }
        public string? Reason { get; init; }
        public long Sequence { get; init; }
        public long BytesTransferred { get; init; }
        public long? TotalBytes { get; init; }
        public IReadOnlyList<DepotManifestUpdateInfo>? Depots { get; init; }
    }
    /// <summary>
    /// Options for prefill operations
    /// </summary>
    public class PrefillOptions
    {
        public int? MaxConcurrency { get; set; }
        /// <summary>
        /// Download all owned games
        /// </summary>
        public bool DownloadAllOwnedGames { get; set; }

        /// <summary>
        /// Include games played in the last 2 weeks
        /// </summary>
        public bool PrefillRecentGames { get; set; }

        /// <summary>
        /// Include recently purchased games (last 2 weeks)
        /// </summary>
        public bool PrefillRecentlyPurchased { get; set; }

        /// <summary>
        /// Number of top games by player count to prefill (null = disabled)
        /// </summary>
        public int? PrefillTopGames { get; set; }

        /// <summary>
        /// Force re-download even if already up to date
        /// </summary>
        public bool Force { get; set; }

        /// <summary>
        /// Target operating systems for downloads. Defaults to the current OS.
        /// </summary>
        public List<OperatingSystem> OperatingSystems { get; set; } = new() { GetCurrentOperatingSystem() };

        public static OperatingSystem GetCurrentOperatingSystem()
        {
            if (System.OperatingSystem.IsLinux())
                return OperatingSystem.Linux;
            if (System.OperatingSystem.IsMacOS())
                return OperatingSystem.MacOS;
            return OperatingSystem.Windows;
        }
    }

    /// <summary>
    /// Result of a prefill operation
    /// </summary>
    public class PrefillResult
    {
        public string? ErrorCode { get; init; }
        public bool? RequiresLogin { get; init; }
        [System.Text.Json.Serialization.JsonIgnore]
        internal Exception? Exception { get; init; }
        public bool Success { get; init; }
        public string? ErrorMessage { get; init; }
        public TimeSpan TotalTime { get; init; }
    }


    /// <summary>
    /// Result of a cache clear operation
    /// </summary>
    public class ClearCacheResult
    {
        public bool Success { get; init; }
        public int FileCount { get; init; }
        public long BytesCleared { get; init; }
        public string? Message { get; init; }
    }


    /// <summary>
    /// Status information for a single app
    /// </summary>
    public class AppStatus
    {
        public uint AppId { get; init; }
        public string Name { get; init; } = "";
        public long DownloadSize { get; init; }
        public bool IsUpToDate { get; init; }
        /// <summary>
        /// If true, this game has no depots for the selected operating systems
        /// </summary>
        public bool IsUnsupportedOs { get; init; }
        /// <summary>
        /// Human-readable reason why the game is unavailable (e.g., "Not available for Linux")
        /// </summary>
        public string? UnavailableReason { get; init; }
    }

    /// <summary>
    /// Status information for all selected apps
    /// </summary>
    public class SelectedAppsStatus
    {
        public List<AppStatus> Apps { get; init; } = new();
        public long TotalDownloadSize { get; init; }
        public string? Message { get; init; }
    }


    /// <summary>
    /// Input for cached depot manifest info from lancache-manager.
    /// Uses camelCase JSON from lancache-manager with manifestId as string for large numbers.
    /// </summary>
    public class CachedDepotInput
    {
        public uint AppId { get; init; }
        public uint DepotId { get; init; }

        [System.Text.Json.Serialization.JsonNumberHandling(System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString)]
        public ulong ManifestId { get; init; }
    }

    /// <summary>
    /// Result of cache status check for all apps.
    /// </summary>
    public class CacheStatusResult
    {
        public List<AppCacheStatus> Apps { get; init; } = new();
        public string? Message { get; init; }
    }

    /// <summary>
    /// Cache status for a single app.
    /// </summary>
    public class AppCacheStatus
    {
        public uint AppId { get; init; }
        public string Name { get; init; } = "";
        public bool IsUpToDate { get; init; }
        public long DownloadSize { get; init; }
        public List<OutdatedDepot> OutdatedDepots { get; init; } = new();
    }

    /// <summary>
    /// Details about an outdated depot that needs updating.
    /// </summary>
    public class OutdatedDepot
    {
        public uint DepotId { get; init; }
        public ulong CachedManifest { get; init; }
        public ulong CurrentManifest { get; init; }
    }

    /// <summary>
    /// Represents an owned game
    /// </summary>
    public class OwnedGame
    {
        public uint AppId { get; init; }
        public string Name { get; init; } = string.Empty;
        public int MinutesPlayedLast2Weeks { get; init; }
        public DateOnly? ReleaseDate { get; init; }
    }

    /// <summary>
    /// Progress update sent via socket for external monitoring
    /// </summary>
    public class PrefillProgressUpdate
    {
        public string? DaemonInstanceId { get; set; }
        public long? Sequence { get; set; }
        public DateTimeOffset? StartedAt { get; set; }
        public string? Reason { get; set; }
        public int SkippedApps { get; set; }
        public int CancelledApps { get; set; }
        public string? OperationId { get; set; }
        public string? ErrorCode { get; set; }
        public bool? RequiresLogin { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("state")]
        public string State { get; set; } = "idle";

        [System.Text.Json.Serialization.JsonPropertyName("message")]
        public string? Message { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("currentAppId")]
        public uint CurrentAppId { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("currentAppName")]
        public string? CurrentAppName { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("totalBytes")]
        public long TotalBytes { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("bytesDownloaded")]
        public long BytesDownloaded { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("percentComplete")]
        public double PercentComplete { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("bytesPerSecond")]
        public double BytesPerSecond { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("elapsed")]
        public TimeSpan Elapsed { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("elapsedSeconds")]
        public double ElapsedSeconds => Elapsed.TotalSeconds;

        [System.Text.Json.Serialization.JsonPropertyName("result")]
        public string? Result { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("errorMessage")]
        public string? ErrorMessage { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("totalApps")]
        public int TotalApps { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("updatedApps")]
        public int UpdatedApps { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("alreadyUpToDate")]
        public int AlreadyUpToDate { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("failedApps")]
        public int FailedApps { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("totalBytesTransferred")]
        public long TotalBytesTransferred { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("totalTime")]
        public TimeSpan TotalTime { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("totalTimeSeconds")]
        public double TotalTimeSeconds => TotalTime.TotalSeconds;

        [System.Text.Json.Serialization.JsonPropertyName("updatedAt")]
        public DateTime UpdatedAt { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("depots")]
        public List<DepotManifestUpdateInfo>? Depots { get; set; }
    }

    /// <summary>
    /// Depot manifest info for cache tracking
    /// </summary>
    public class DepotManifestUpdateInfo
    {
        [System.Text.Json.Serialization.JsonPropertyName("depotId")]
        public uint DepotId { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("manifestId")]
        public ulong ManifestId { get; set; }

        [System.Text.Json.Serialization.JsonPropertyName("totalBytes")]
        public long TotalBytes { get; set; }
    }

    /// <summary>
    /// Auto-login credentials format for secure token exchange
    /// </summary>
    public sealed class AutoLoginCredentials
    {
        public string Username { get; init; } = string.Empty;
        public string RefreshToken { get; init; } = string.Empty;
    }

    /// <summary>
    /// Status data returned by the status command
    /// </summary>
    public class StatusData
    {
        public bool RestartRequired { get; init; }
        public int ProtocolVersion { get; init; }
        public IReadOnlyList<string> Features { get; init; } = Array.Empty<string>();
        public string? DaemonInstanceId { get; init; }
        public int MaxConcurrentRuns { get; init; }
        public int MaxConcurrentRequests { get; init; }
        public int RetentionHours { get; init; } = LancachePrefill.Common.PrefillProtocol.RetentionHours;
        public int RetentionOperations { get; init; } = LancachePrefill.Common.PrefillProtocol.RetentionOperations;
        public int RetentionItems { get; init; } = LancachePrefill.Common.PrefillProtocol.RetentionItems;
        public IReadOnlyList<LancachePrefill.Common.RunSnapshot> ActiveOperations { get; init; } = Array.Empty<LancachePrefill.Common.RunSnapshot>();
        public IReadOnlyList<LancachePrefill.Common.RunSnapshot> RecentOperations { get; init; } = Array.Empty<LancachePrefill.Common.RunSnapshot>();
        public bool IsLoggedIn { get; init; }
        public bool IsInitialized { get; init; }

        /// <summary>
        /// UTC expiry of the stored refresh-token JWT (ISO-8601), or null when not logged in / no token.
        /// Lets a manager show a login-expiry countdown.
        /// </summary>
        public DateTime? AuthExpiryUtc { get; init; }

        /// <summary>
        /// The logged-in Steam account username, or null when not available.
        /// </summary>
        public string? Username { get; init; }
    }

    /// <summary>
    /// Command request sent from client to daemon via socket
    /// </summary>
    public class CommandRequest
    {
        /// <summary>
        /// Unique request ID for tracking
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Command type (login, logout, prefill, status, etc.)
        /// </summary>
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// Command parameters (varies by command type)
        /// </summary>
        public Dictionary<string, string>? Parameters { get; set; }

        /// <summary>
        /// Timestamp when command was created
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Command response sent from daemon to client via socket
    /// </summary>
    public class CommandResponse
    {
        public string? ErrorCode { get; set; }
        /// <summary>
        /// Request ID this response corresponds to
        /// </summary>
        public string Id { get; set; } = string.Empty;

        /// <summary>
        /// Whether the command succeeded
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Human-readable message
        /// </summary>
        public string? Message { get; set; }

        /// <summary>
        /// Error message if failed
        /// </summary>
        public string? Error { get; set; }

        /// <summary>
        /// Response data (varies by command type)
        /// </summary>
        public object? Data { get; set; }

        /// <summary>
        /// Whether login is required
        /// </summary>
        public bool RequiresLogin { get; set; }

        /// <summary>
        /// Timestamp when response was created
        /// </summary>
        public DateTime CompletedAt { get; set; } = DateTime.UtcNow;
    }

    public enum LogLevel
    {
        Debug,
        Info,
        Warning,
        Error
    }

    public class AppDownloadInfo
    {
        public string? Reason { get; init; }
        public uint AppId { get; init; }
        public string Name { get; init; } = string.Empty;
        public long TotalBytes { get; init; }
        public int ChunkCount { get; init; }

        /// <summary>
        /// List of depots that were downloaded, with their manifest IDs.
        /// Used for cache tracking to detect when games need re-downloading.
        /// </summary>
        public List<DepotManifestInfo>? Depots { get; init; }
    }

    public class DepotManifestInfo
    {
        public uint DepotId { get; init; }
        public ulong ManifestId { get; init; }
        public long TotalBytes { get; init; }
    }

    public class DownloadProgressInfo
    {
        public uint AppId { get; init; }
        public string AppName { get; init; } = string.Empty;
        public long BytesDownloaded { get; init; }
        public long TotalBytes { get; init; }
        public double PercentComplete => TotalBytes > 0 ? (double)BytesDownloaded / TotalBytes * 100 : 0;
        public double BytesPerSecond { get; init; }
        public TimeSpan Elapsed { get; init; }
    }

    public enum AppDownloadResult
    {
        Success,
        AlreadyUpToDate,
        Failed,
        Skipped,
        NoDepotsToDownload
    }

    public class PrefillSummary
    {
        public int TotalApps { get; init; }
        public int UpdatedApps { get; init; }
        public int AlreadyUpToDate { get; init; }
        public int FailedApps { get; init; }
        public int UnownedApps { get; init; }
        public long TotalBytesTransferred { get; init; }
        public TimeSpan TotalTime { get; init; }
    }

    /// <summary>
    /// Event message sent from server to client (unsolicited).
    /// </summary>
    public class SocketEvent<T>
    {
        public string Type { get; init; } = string.Empty;
        public T? Data { get; init; }
        public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Credential challenge event sent when login requires credentials.
    /// </summary>
    public class CredentialChallengeEvent : SocketEvent<CredentialChallenge>
    {
        public CredentialChallengeEvent(CredentialChallenge challenge)
        {
            Type = "credential-challenge";
            Data = challenge;
        }
    }

    /// <summary>
    /// Progress event sent during prefill operations.
    /// </summary>
    public class ProgressEvent : SocketEvent<PrefillProgressUpdate>
    {
        public ProgressEvent(PrefillProgressUpdate progress)
        {
            Type = "progress";
            Data = progress;
        }
    }

    /// <summary>
    /// Auth state change event.
    /// </summary>
    public class AuthStateEvent : SocketEvent<AuthStateData>
    {
        public AuthStateEvent(string state, string? message = null)
        {
            Type = "auth-state";
            Data = new AuthStateData { State = state, Message = message };
        }
    }

    public class AuthStateData
    {
        public string State { get; init; } = string.Empty;
        public string? Message { get; init; }
    }

    public enum SocketServerMode
    {
        UnixSocket,
        Tcp
    }
}

namespace SteamPrefill.Handlers.Steam
{
    public sealed class UserLicenses
    {
        public HashSet<uint> OwnedPackageIds { get; } = new HashSet<uint>();
        public HashSet<uint> OwnedAppIds { get; } = new HashSet<uint>();
        public HashSet<uint> OwnedDepotIds { get; } = new HashSet<uint>();

        public override string ToString()
        {
            return $"Packages : {OwnedPackageIds.Count} Apps : {OwnedAppIds.Count} Depots : {OwnedDepotIds.Count}";
        }
    }
}
