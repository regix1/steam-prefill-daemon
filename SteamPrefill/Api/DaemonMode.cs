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

        var progress = new SecureConsoleProgress();

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
    /// Secure console progress reporter that avoids logging sensitive data
    /// </summary>
    private sealed class SecureConsoleProgress : IPrefillProgress
    {
        // Patterns that might contain sensitive data - never log these
        private static readonly string[] SensitivePatterns = new[]
        {
            "password", "credential", "secret", "token", "auth", "2fa", "code"
        };

        public void OnLog(LogLevel level, string message)
        {
            // Check for potentially sensitive content
            if (ContainsSensitiveContent(message))
            {
                // Log sanitized version
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
                // Only flag if it looks like actual credential content, not just mentions
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
            // Don't spam console with progress updates
        }

        public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result)
            => OnLog(LogLevel.Info, $"Completed: {app.Name} - {result}");

        public void OnPrefillCompleted(PrefillSummary summary)
            => OnLog(LogLevel.Info, $"Prefill complete: {summary.UpdatedApps} updated, {summary.AlreadyUpToDate} up-to-date, {summary.FailedApps} failed");

        public void OnError(string message, Exception? exception = null)
        {
            // Sanitize error messages too
            if (ContainsSensitiveContent(message))
            {
                message = "[REDACTED - Sensitive content in error]";
            }

            OnLog(LogLevel.Error, message);
            if (exception != null)
            {
                // Don't log exception details that might contain credentials
                Console.WriteLine($"Exception type: {exception.GetType().Name}");
            }
        }
    }
}
