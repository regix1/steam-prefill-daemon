#nullable enable

namespace SteamPrefill.Api;

/// <summary>
/// Interface for receiving progress updates during prefill operations.
/// Implement this to receive updates for UI, logging, etc.
/// </summary>
public interface IPrefillProgress
{
    /// <summary>
    /// Called when a log message is generated
    /// </summary>
    void OnLog(LogLevel level, string message);

    /// <summary>
    /// Called when an operation starts
    /// </summary>
    void OnOperationStarted(string operationName);

    /// <summary>
    /// Called when an operation completes
    /// </summary>
    void OnOperationCompleted(string operationName, TimeSpan elapsed);

    /// <summary>
    /// Called when an app download starts
    /// </summary>
    void OnAppStarted(AppDownloadInfo app);

    /// <summary>
    /// Called periodically during download with progress info
    /// </summary>
    void OnDownloadProgress(DownloadProgressInfo progress);

    /// <summary>
    /// Called when an app download completes
    /// </summary>
    void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result);

    /// <summary>
    /// Called when the entire prefill operation completes
    /// </summary>
    void OnPrefillCompleted(PrefillSummary summary);

    /// <summary>
    /// Called when an error occurs
    /// </summary>
    void OnError(string message, Exception? exception = null);
}


/// <summary>
/// Default no-op implementation that discards all progress events
/// </summary>
public class NullProgress : IPrefillProgress
{
    public static readonly NullProgress Instance = new();

    public void OnLog(LogLevel level, string message) { }
    public void OnOperationStarted(string operationName) { }
    public void OnOperationCompleted(string operationName, TimeSpan elapsed) { }
    public void OnAppStarted(AppDownloadInfo app) { }
    public void OnDownloadProgress(DownloadProgressInfo progress) { }
    public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result) { }
    public void OnPrefillCompleted(PrefillSummary summary) { }
    public void OnError(string message, Exception? exception = null) { }
}

/// <summary>
/// Implementation that forwards progress to callbacks/events.
/// Useful for integrating with web sockets, SignalR, etc.
/// </summary>
public class CallbackProgress : IPrefillProgress
{
    public event Action<LogLevel, string>? LogReceived;
    public event Action<string>? OperationStarted;
    public event Action<string, TimeSpan>? OperationCompleted;
    public event Action<AppDownloadInfo>? AppStarted;
    public event Action<DownloadProgressInfo>? DownloadProgressUpdated;
    public event Action<AppDownloadInfo, AppDownloadResult>? AppCompleted;
    public event Action<PrefillSummary>? PrefillCompleted;
    public event Action<string, Exception?>? ErrorOccurred;

    public void OnLog(LogLevel level, string message) => LogReceived?.Invoke(level, message);
    public void OnOperationStarted(string operationName) => OperationStarted?.Invoke(operationName);
    public void OnOperationCompleted(string operationName, TimeSpan elapsed) => OperationCompleted?.Invoke(operationName, elapsed);
    public void OnAppStarted(AppDownloadInfo app) => AppStarted?.Invoke(app);
    public void OnDownloadProgress(DownloadProgressInfo progress) => DownloadProgressUpdated?.Invoke(progress);
    public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result) => AppCompleted?.Invoke(app, result);
    public void OnPrefillCompleted(PrefillSummary summary) => PrefillCompleted?.Invoke(summary);
    public void OnError(string message, Exception? exception = null) => ErrorOccurred?.Invoke(message, exception);
}
