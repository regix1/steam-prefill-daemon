using System.Text.Json.Serialization;

#nullable enable

namespace SteamPrefill.Api;

[JsonConverter(typeof(JsonStringEnumConverter<CacheOutcome>))]
public enum CacheOutcome
{
    Current,
    Outdated,
    Unknown
}

[JsonConverter(typeof(JsonStringEnumConverter<CacheReason>))]
public enum CacheReason
{
    UnsupportedDaemon,
    Disconnected,
    ConnectionChanged,
    StatusUnavailable,
    InvalidResult,
    InvalidAppId,
    MissingApp,
    LinkedDepotUnavailable,
    ManifestUnavailable,
    UnsupportedOs,
    NoContent,
    NoCacheEvidence,
    InspectionFailed,
    DeadlineReached,
    AuthenticationRequired
}

[JsonConverter(typeof(JsonStringEnumConverter<CacheAuthority>))]
public enum CacheAuthority
{
    Absent,
    Empty,
    Snapshot
}

public sealed class CacheAppScope
{
    public uint AppId { get; init; }
    public CacheAuthority? Authority { get; init; }
}
