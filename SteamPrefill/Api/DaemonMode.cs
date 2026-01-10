#nullable enable

namespace SteamPrefill.Api;

/// <summary>
/// Runs SteamPrefill in daemon mode, accepting commands via files.
/// This is the recommended way to run SteamPrefill in a Docker container for web integration.
///
/// Security features:
/// - Login required before any commands
/// - Encrypted credential exchange (ECDH + AES-GCM)
/// - Plain text passwords never written to disk
/// - Secure memory handling for credentials
/// </summary>
public static class DaemonMode
{
    /// <summary>
    /// Run in secure file-based daemon mode.
    /// Commands are written to /commands, responses written to /responses.
    /// All credentials are encrypted using ECDH key exchange and AES-GCM.
    /// </summary>
    public static async Task RunFileBasedAsync(
        string commandsDir = "/commands",
        string responsesDir = "/responses",
        CancellationToken cancellationToken = default)
    {
        Console.WriteLine("Starting SteamPrefill in SECURE daemon mode...");
        Console.WriteLine($"Commands directory: {commandsDir}");
        Console.WriteLine($"Responses directory: {responsesDir}");
        Console.WriteLine();
        Console.WriteLine("┌──────────────────────────────────────────────────────────────┐");
        Console.WriteLine("│ SECURITY NOTICE                                              │");
        Console.WriteLine("├──────────────────────────────────────────────────────────────┤");
        Console.WriteLine("│ • Login is REQUIRED before any other commands                │");
        Console.WriteLine("│ • All credentials are encrypted using ECDH + AES-GCM         │");
        Console.WriteLine("│ • Plain text passwords are NEVER written to disk             │");
        Console.WriteLine("│ • Challenges expire after 5 minutes                          │");
        Console.WriteLine("└──────────────────────────────────────────────────────────────┘");
        Console.WriteLine();

        var progress = new FileBasedProgress(responsesDir);

        using var secureInterface = new SecureFileCommandInterface(
            commandsDir,
            responsesDir,
            progress);

        await secureInterface.StartAsync(cancellationToken);

        Console.WriteLine("Daemon started. Waiting for login command...");
        Console.WriteLine();
        Console.WriteLine("To login, write a command file like:");
        Console.WriteLine("  {\"type\": \"login\", \"id\": \"unique-id\"}");
        Console.WriteLine();
        Console.WriteLine("Then respond to credential challenges with encrypted credentials.");

        // Keep running until cancelled
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Daemon shutdown requested...");
        }

        secureInterface.Stop();
        Console.WriteLine("Daemon stopped.");
    }

    /// <summary>
    /// File-based progress reporter that writes progress to a JSON file for external monitoring.
    /// Also logs to console with sanitization.
    /// </summary>
    private sealed class FileBasedProgress : IPrefillProgress
    {
        private readonly string _responsesDir;
        private readonly string _progressFile;
        private readonly object _lock = new();
        private DateTime _lastWrite = DateTime.MinValue;
        private static readonly TimeSpan WriteThrottle = TimeSpan.FromMilliseconds(250);

        // Patterns that might contain sensitive data - never log these
        private static readonly string[] SensitivePatterns = new[]
        {
            "password", "credential", "secret", "token", "auth", "2fa", "code"
        };

        public FileBasedProgress(string responsesDir)
        {
            _responsesDir = responsesDir;
            _progressFile = Path.Combine(responsesDir, "prefill_progress.json");
        }

        public void OnLog(LogLevel level, string message)
        {
            // Filter out Spectre.Console type names
            if (message.StartsWith("Spectre.Console."))
                return;

            // Check for potentially sensitive content
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

            // Write progress updates for important status messages
            // This ensures the frontend can see metadata loading progress
            if (level == LogLevel.Info && IsProgressMessage(message))
            {
                var state = GetStateFromMessage(message);
                WriteProgress(new PrefillProgressUpdate
                {
                    State = state,
                    Message = message,
                    UpdatedAt = DateTime.UtcNow
                });
            }
        }

        /// <summary>
        /// Determines if a message should trigger a progress file update
        /// </summary>
        private static bool IsProgressMessage(string message)
        {
            return message.Contains("Loading metadata") ||
                   message.Contains("Metadata loaded") ||
                   message.Contains("Starting prefill of") ||
                   message.Contains("apps selected") ||
                   message.Contains("Starting login") ||
                   message.Contains("Login successful");
        }

        /// <summary>
        /// Determines the state based on the message content
        /// </summary>
        private static string GetStateFromMessage(string message)
        {
            if (message.Contains("Loading metadata"))
                return "loading-metadata";
            if (message.Contains("Metadata loaded"))
                return "metadata-loaded";
            if (message.Contains("Starting prefill"))
                return "starting";
            if (message.Contains("Login successful"))
                return "logged-in";
            return "preparing";
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
        {
            OnLog(LogLevel.Info, $"Downloading: {app.Name} ({app.AppId})");
            WriteProgress(new PrefillProgressUpdate
            {
                State = "downloading",
                CurrentAppId = app.AppId,
                CurrentAppName = app.Name,
                TotalBytes = app.TotalBytes,
                BytesDownloaded = 0,
                PercentComplete = 0,
                UpdatedAt = DateTime.UtcNow
            });
        }

        public void OnDownloadProgress(DownloadProgressInfo progress)
        {
            // Throttle writes to avoid excessive I/O
            var now = DateTime.UtcNow;
            if (now - _lastWrite < WriteThrottle)
                return;

            // Log progress to console
            var speedMBps = progress.BytesPerSecond / 1024.0 / 1024.0;
            Console.WriteLine($"{DateTime.UtcNow:HH:mm:ss} [PROGRESS] {progress.AppName}: {progress.PercentComplete:F1}% @ {speedMBps:F1} MB/s");

            WriteProgress(new PrefillProgressUpdate
            {
                State = "downloading",
                CurrentAppId = progress.AppId,
                CurrentAppName = progress.AppName,
                TotalBytes = progress.TotalBytes,
                BytesDownloaded = progress.BytesDownloaded,
                PercentComplete = progress.PercentComplete,
                BytesPerSecond = progress.BytesPerSecond,
                Elapsed = progress.Elapsed,
                UpdatedAt = DateTime.UtcNow
            });
        }

        public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result)
        {
            OnLog(LogLevel.Info, $"Completed: {app.Name} - {result}");

            // Determine bytes downloaded based on result
            // Success = downloaded full size, AlreadyUpToDate/Skipped = 0 bytes transferred
            var bytesDownloaded = result == AppDownloadResult.Success ? app.TotalBytes : 0;

            WriteProgress(new PrefillProgressUpdate
            {
                State = "app_completed",
                CurrentAppId = app.AppId,
                CurrentAppName = app.Name,
                TotalBytes = app.TotalBytes,
                BytesDownloaded = bytesDownloaded,
                Result = result.ToString(),
                // Include depot manifest info for cache tracking
                Depots = app.Depots?.Select(d => new DepotManifestUpdateInfo
                {
                    DepotId = d.DepotId,
                    ManifestId = d.ManifestId,
                    TotalBytes = d.TotalBytes
                }).ToList(),
                UpdatedAt = DateTime.UtcNow
            });
        }

        public void OnPrefillCompleted(PrefillSummary summary)
        {
            OnLog(LogLevel.Info, $"Prefill complete: {summary.UpdatedApps} updated, {summary.AlreadyUpToDate} up-to-date, {summary.FailedApps} failed");
            WriteProgress(new PrefillProgressUpdate
            {
                State = "completed",
                TotalApps = summary.TotalApps,
                UpdatedApps = summary.UpdatedApps,
                AlreadyUpToDate = summary.AlreadyUpToDate,
                FailedApps = summary.FailedApps,
                TotalBytesTransferred = summary.TotalBytesTransferred,
                TotalTime = summary.TotalTime,
                UpdatedAt = DateTime.UtcNow
            });

            // Delete progress file after completion
            try { File.Delete(_progressFile); } catch { }
        }

        public void OnError(string message, Exception? exception = null)
        {
            if (ContainsSensitiveContent(message))
            {
                message = "[REDACTED - Sensitive content in error]";
            }

            OnLog(LogLevel.Error, message);
            WriteProgress(new PrefillProgressUpdate
            {
                State = "error",
                ErrorMessage = message,
                UpdatedAt = DateTime.UtcNow
            });
        }

        private void WriteProgress(PrefillProgressUpdate update)
        {
            lock (_lock)
            {
                try
                {
                    var json = System.Text.Json.JsonSerializer.Serialize(update, DaemonSerializationContext.Default.PrefillProgressUpdate);
                    File.WriteAllText(_progressFile, json);
                    _lastWrite = DateTime.UtcNow;
                }
                catch
                {
                    // Ignore write errors
                }
            }
        }
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
