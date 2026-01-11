#nullable enable

namespace SteamPrefill.Api;

/// <summary>
/// Runs SteamPrefill in daemon mode using SignalR for real-time communication.
/// This is the recommended way to run SteamPrefill in a Docker container for web integration.
///
/// Security features:
/// - Login required before any commands
/// - Encrypted credential exchange (ECDH + AES-GCM)
/// - Real-time communication via SignalR WebSocket
/// - Secure memory handling for credentials
/// </summary>
public static class DaemonMode
{
    /// <summary>
    /// Run in SignalR-based daemon mode.
    /// Connects directly to the API via SignalR for real-time communication.
    /// </summary>
    public static async Task RunSignalRAsync(
        string apiUrl,
        string sessionId,
        CancellationToken cancellationToken = default)
    {
        Console.WriteLine("Starting SteamPrefill in SignalR daemon mode...");
        Console.WriteLine($"API URL: {apiUrl}");
        Console.WriteLine($"Session ID: {sessionId}");
        Console.WriteLine();
        Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
        Console.WriteLine("│ SECURITY NOTICE                                              │");
        Console.WriteLine("├──────────────────────────────────────────────────────────────┤");
        Console.WriteLine("│ • Login is REQUIRED before any other commands                │");
        Console.WriteLine("│ • All credentials are encrypted using ECDH + AES-GCM         │");
        Console.WriteLine("│ • Communication via secure SignalR WebSocket connection      │");
        Console.WriteLine("└──────────────────────────────────────────────────────────────┘");
        Console.WriteLine();

        var progress = new ConsoleProgress();

        await using var client = new SignalRDaemonClient(apiUrl, sessionId, progress);
        
        try
        {
            await client.ConnectAsync(cancellationToken);
            Console.WriteLine("Connected to API. Waiting for commands...");

            // Keep running until cancelled
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Daemon shutdown requested...");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Daemon error: {ex.Message}");
            throw;
        }

        Console.WriteLine("Daemon stopped.");
    }

    /// <summary>
    /// Auto-detect API URL from Docker network or environment
    /// </summary>
    public static string? AutoDetectApiUrl()
    {
        // Check environment variable first
        var envUrl = Environment.GetEnvironmentVariable("LANCACHE_API_URL");
        if (!string.IsNullOrEmpty(envUrl))
        {
            Console.WriteLine($"Using API URL from environment: {envUrl}");
            return envUrl;
        }

        // Try common Docker service names
        var possibleHosts = new[]
        {
            "lancache-manager",
            "lancache-manager-api",
            "api",
            "host.docker.internal"
        };

        var possiblePorts = new[] { "5000", "80", "8080" };

        foreach (var host in possibleHosts)
        {
            foreach (var port in possiblePorts)
            {
                var url = $"http://{host}:{port}";
                Console.WriteLine($"Checking {url}...");
                
                try
                {
                    using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                    var response = httpClient.GetAsync($"{url}/health").GetAwaiter().GetResult();
                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"Found API at {url}");
                        return url;
                    }
                }
                catch
                {
                    // Not available, try next
                }
            }
        }

        Console.WriteLine("Could not auto-detect API URL");
        return null;
    }

    /// <summary>
    /// Console-based progress reporter for daemon mode
    /// </summary>
    private sealed class ConsoleProgress : IPrefillProgress
    {
        private static readonly string[] SensitivePatterns = new[]
        {
            "password", "credential", "secret", "token", "auth", "2fa", "code"
        };

        public void OnLog(LogLevel level, string message)
        {
            if (message.StartsWith("Spectre.Console."))
                return;

            if (ContainsSensitiveContent(message))
            {
                message = "[REDACTED - Sensitive content]";
            }

            var prefix = level switch
            {
                LogLevel.Debug => "[DEBUG]",
                LogLevel.Info => "[INFO]",
                LogLevel.Warning => "[WARN]",
                LogLevel.Error => "[ERROR]",
                _ => "[LOG]"
            };
            Console.WriteLine($"{DateTime.UtcNow:HH:mm:ss} {prefix} {message}");
        }

        private static bool ContainsSensitiveContent(string message)
        {
            var lower = message.ToLowerInvariant();
            foreach (var pattern in SensitivePatterns)
            {
                if (lower.Contains($"{pattern}=") ||
                    lower.Contains($"{pattern}:") ||
                    lower.Contains($"\"{pattern}\""))
                {
                    return true;
                }
            }
            return false;
        }

        public void OnOperationStarted(string operationName)
            => OnLog(LogLevel.Info, $"Starting: {operationName}");

        public void OnOperationCompleted(string operationName, TimeSpan elapsed)
            => OnLog(LogLevel.Info, $"Completed: {operationName} ({elapsed.TotalSeconds:F2}s)");

        public void OnAppStarted(AppDownloadInfo app)
            => OnLog(LogLevel.Info, $"Downloading: {app.Name} ({app.AppId})");

        public void OnDownloadProgress(DownloadProgressInfo progress)
        {
            var speedMBps = progress.BytesPerSecond / 1024.0 / 1024.0;
            Console.WriteLine($"{DateTime.UtcNow:HH:mm:ss} [PROGRESS] {progress.AppName}: {progress.PercentComplete:F1}% @ {speedMBps:F1} MB/s");
        }

        public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result)
            => OnLog(LogLevel.Info, $"Completed: {app.Name} - {result}");

        public void OnPrefillCompleted(PrefillSummary summary)
            => OnLog(LogLevel.Info, $"Prefill complete: {summary.UpdatedApps} updated, {summary.AlreadyUpToDate} up-to-date, {summary.FailedApps} failed");

        public void OnError(string message, Exception? exception = null)
            => OnLog(LogLevel.Error, message);
    }
}

/// <summary>
/// Progress update written to file for external monitoring
/// </summary>
public class PrefillProgressUpdate
{
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
