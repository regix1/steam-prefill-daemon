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
internal sealed partial class DaemonSerializationContext : JsonSerializerContext
{
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
/// Daemon status update written to responses directory
/// </summary>
public class DaemonStatus
{
    public string Type { get; init; } = "status-update";
    public string Status { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; }
}
