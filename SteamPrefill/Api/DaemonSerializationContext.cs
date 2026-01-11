using System.Text.Json.Serialization;

namespace SteamPrefill.Api;

/// <summary>
/// JSON serialization context for daemon API types.
/// Uses source generation for AOT compatibility.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CommandRequest))]
[JsonSerializable(typeof(CommandResponse))]
[JsonSerializable(typeof(CredentialChallenge))]
[JsonSerializable(typeof(EncryptedCredentialResponse))]
[JsonSerializable(typeof(DaemonStatus))]
[JsonSerializable(typeof(List<OwnedGame>))]
[JsonSerializable(typeof(List<uint>))]
[JsonSerializable(typeof(PrefillResult))]
[JsonSerializable(typeof(StatusData))]
[JsonSerializable(typeof(PrefillProgressUpdate))]
[JsonSerializable(typeof(ClearCacheResult))]
[JsonSerializable(typeof(AppStatus))]
[JsonSerializable(typeof(SelectedAppsStatus))]
[JsonSerializable(typeof(DepotManifestUpdateInfo))]
[JsonSerializable(typeof(List<DepotManifestUpdateInfo>))]
[JsonSerializable(typeof(CacheStatusResult))]
[JsonSerializable(typeof(CachedDepotInput))]
[JsonSerializable(typeof(List<CachedDepotInput>))]
[JsonSerializable(typeof(object))] // Required for polymorphic Data property in CommandResponse
[JsonSerializable(typeof(PrefillCommandOptions))]
[JsonSerializable(typeof(GetStatusCommandOptions))]
internal sealed partial class DaemonSerializationContext : JsonSerializerContext
{
}

/// <summary>
/// Options for prefill command (received from API via SignalR)
/// </summary>
public class PrefillCommandOptions
{
    public bool All { get; set; }
    public bool Recent { get; set; }
    public bool Force { get; set; }
    public List<string>? OperatingSystems { get; set; }
    public List<CachedDepotInput>? CachedDepots { get; set; }
}

/// <summary>
/// Options for get-selected-apps-status command
/// </summary>
public class GetStatusCommandOptions
{
    public List<string>? OperatingSystems { get; set; }
    public List<CachedDepotInput>? CachedDepots { get; set; }
}

/// <summary>
/// Status data returned by the status command
/// </summary>
public class StatusData
{
    public bool IsLoggedIn { get; init; }
    public bool IsInitialized { get; init; }
}

/// <summary>
/// Daemon status update
/// </summary>
public class DaemonStatus
{
    public string Type { get; init; } = "status-update";
    public string Status { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; }
}

/// <summary>
/// Command request format for SignalR communication
/// </summary>
public class CommandRequest
{
    /// <summary>
    /// Unique ID for this command (for correlating responses)
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Command type: login, get-owned-games, set-selected-apps, prefill, etc.
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Optional parameters for the command
    /// </summary>
    public Dictionary<string, string>? Parameters { get; set; }

    /// <summary>
    /// When the command was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Command response format
/// </summary>
public class CommandResponse
{
    /// <summary>
    /// ID matching the request
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Whether the command succeeded
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Optional success message
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Error message if failed
    /// </summary>
    public string? Error { get; set; }

    /// <summary>
    /// Response data (varies by command)
    /// </summary>
    public object? Data { get; set; }

    /// <summary>
    /// If true, login is required before this command can be executed
    /// </summary>
    public bool? RequiresLogin { get; set; }

    /// <summary>
    /// When the command completed
    /// </summary>
    public DateTime CompletedAt { get; set; }
}
