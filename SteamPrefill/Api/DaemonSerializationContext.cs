using System.Text.Json.Serialization;

#nullable enable annotations

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
[JsonSerializable(typeof(List<OwnedGame>))]
[JsonSerializable(typeof(List<uint>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(LancachePrefill.Common.RunSnapshot))]
[JsonSerializable(typeof(LancachePrefill.Common.OperationPage))]
[JsonSerializable(typeof(PrefillStart))]
[JsonSerializable(typeof(PrefillPage))]
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
[JsonSerializable(typeof(CacheAppScope))]
[JsonSerializable(typeof(List<CacheAppScope>))]
// Socket event types
[JsonSerializable(typeof(SocketEvent<CredentialChallenge>))]
[JsonSerializable(typeof(SocketEvent<PrefillProgressUpdate>))]
[JsonSerializable(typeof(SocketEvent<AuthStateData>))]
[JsonSerializable(typeof(AuthStateData))]
[JsonSerializable(typeof(object))] // Required for polymorphic Data property in CommandResponse
[JsonSerializable(typeof(AutoLoginCredentials))]
internal sealed partial class DaemonSerializationContext : JsonSerializerContext
{
}
