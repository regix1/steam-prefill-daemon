#nullable enable

using SteamPrefill.Models;
using SteamPrefill.Models.Enums;

namespace SteamPrefill.Api;

/// <summary>
/// High-level programmatic API for Steam Prefill operations.
/// Use this instead of SteamManager for non-CLI applications.
/// </summary>
public sealed class SteamPrefillApi : IDisposable
{
    private readonly ISteamAuthProvider _authProvider;
    private readonly IPrefillProgress _progress;
    private readonly PrefillApiSession? _session;

    private SteamManager? _steamManager;

    // In-memory cache for selected apps in daemon mode - avoids file I/O issues in containers
    private List<uint>? _selectedAppsCache;
    private bool _isInitialized;
    private bool _isDisposed;

    /// <summary>
    /// Creates a new Steam Prefill API instance
    /// </summary>
    /// <param name="authProvider">Provider for Steam authentication credentials</param>
    /// <param name="progress">Optional progress reporter for status updates</param>
    /// <param name="session">Optional session for storing/loading credentials between runs</param>
    public SteamPrefillApi(
        ISteamAuthProvider authProvider,
        IPrefillProgress? progress = null,
        PrefillApiSession? session = null)
    {
        _authProvider = authProvider ?? throw new ArgumentNullException(nameof(authProvider));
        _progress = progress ?? NullProgress.Instance;
        _session = session;
    }

    /// <summary>
    /// Whether the API is initialized and logged into Steam
    /// </summary>
    public bool IsInitialized => _isInitialized;

    /// <summary>
    /// Initializes the API and logs into Steam.
    /// Must be called before any other operations.
    /// </summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (_isInitialized)
            return;

        _progress.OnOperationStarted("Initializing Steam connection");
        var timer = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            // Create console adapter that routes through our auth provider
            var consoleAdapter = new ApiConsoleAdapter(_authProvider, _progress);

            var downloadArgs = new DownloadArguments
            {
                Force = false,
                TransferSpeedUnit = TransferSpeedUnit.Bits,
                OperatingSystems = new List<OperatingSystem> { PrefillOptions.GetCurrentOperatingSystem() }
            };

            _steamManager = new SteamManager(consoleAdapter, downloadArgs, _authProvider, _progress);

            await _steamManager.InitializeAsync(cancellationToken);
            _isInitialized = true;

            _progress.OnOperationCompleted("Initializing Steam connection", timer.Elapsed);
            _progress.OnLog(LogLevel.Info, "Successfully logged into Steam");
        }
        catch (Exception ex)
        {
            _progress.OnError("Failed to initialize Steam connection", ex);
            throw;
        }
    }

    /// <summary>
    /// Gets all games owned by the logged-in user
    /// </summary>
    public async Task<List<OwnedGame>> GetOwnedGamesAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfNotInitialized();
        ThrowIfDisposed();

        _progress.OnOperationStarted("Fetching owned games");
        var timer = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            var apps = await _steamManager!.GetAllAvailableAppsAsync();
            var result = apps.Select(a => new OwnedGame
            {
                AppId = a.AppId,
                Name = a.Name,
                MinutesPlayedLast2Weeks = a.MinutesPlayed2Weeks ?? 0,
                ReleaseDate = a.ReleaseDate.HasValue ? DateOnly.FromDateTime(a.ReleaseDate.Value) : null
            }).ToList();

            _progress.OnOperationCompleted("Fetching owned games", timer.Elapsed);
            return result;
        }
        catch (Exception ex)
        {
            _progress.OnError("Failed to fetch owned games", ex);
            throw;
        }
    }

    /// <summary>
    /// Gets the list of previously selected app IDs
    /// </summary>
    public List<uint> GetSelectedApps()
    {
        ThrowIfNotInitialized();
        ThrowIfDisposed();

        // Prefer in-memory cache for daemon mode reliability
        if (_selectedAppsCache != null && _selectedAppsCache.Count > 0)
        {
            _progress.OnLog(LogLevel.Info, $"GetSelectedApps: Returning {_selectedAppsCache.Count} cached apps");
            return _selectedAppsCache;
        }

        // Fall back to file-based storage for CLI mode
        var fileApps = _steamManager!.LoadPreviouslySelectedApps();
        _progress.OnLog(LogLevel.Info, $"GetSelectedApps: Loaded {fileApps.Count} apps from file");
        return fileApps;
    }


    /// <summary>
    /// Gets detailed status information for selected apps including download sizes.
    /// Requires login to be completed.
    /// </summary>
    public async Task<SelectedAppsStatus> GetSelectedAppsStatusAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfNotInitialized();
        ThrowIfDisposed();

        var appIds = GetSelectedApps();
        
        if (appIds.Count == 0)
        {
            return new SelectedAppsStatus
            {
                Apps = new List<AppStatus>(),
                TotalDownloadSize = 0,
                Message = "No apps selected"
            };
        }

        try
        {
            var appStatuses = await _steamManager!.GetSelectedAppsStatusAsync(appIds);
            var totalSize = appStatuses.Sum(a => a.DownloadSize);
            var totalSizeFormatted = ByteSize.FromBytes(totalSize);

            return new SelectedAppsStatus
            {
                Apps = appStatuses,
                TotalDownloadSize = totalSize,
                Message = $"{appStatuses.Count} apps selected, {totalSizeFormatted.ToDecimalString()} total"
            };
        }
        catch (Exception ex)
        {
            _progress.OnError("Failed to get selected apps status", ex);
            return new SelectedAppsStatus
            {
                Apps = new List<AppStatus>(),
                TotalDownloadSize = 0,
                Message = $"Error: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Sets the list of app IDs to prefill
    /// </summary>
    public void SetSelectedApps(IEnumerable<uint> appIds)
    {
        ThrowIfNotInitialized();
        ThrowIfDisposed();

        var appIdList = appIds.ToList();
        
        // Cache in memory for daemon mode reliability
        _selectedAppsCache = appIdList;

        var tuiApps = appIdList.Select(id => new TuiAppInfo(id.ToString(), "")
        {
            IsSelected = true
        }).ToList();

        _steamManager!.SetAppsAsSelected(tuiApps);
        _progress.OnLog(LogLevel.Info, $"Set {tuiApps.Count} apps for prefill (cached in memory)");
    }

    /// <summary>
    /// Runs the prefill operation with the specified options
    /// </summary>
    public async Task<PrefillResult> PrefillAsync(
        PrefillOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotInitialized();
        ThrowIfDisposed();

        options ??= new PrefillOptions();

        // Update download options before starting
        _steamManager!.UpdateDownloadOptions(
            force: options.Force,
            operatingSystems: options.OperatingSystems);

        _progress.OnOperationStarted("Prefill operation");
        var timer = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            await _steamManager!.DownloadMultipleAppsAsync(
                downloadAllOwnedGames: options.DownloadAllOwnedGames,
                prefillRecentGames: options.PrefillRecentGames,
                prefillPopularGames: options.PrefillTopGames,
                prefillRecentlyPurchasedGames: options.PrefillRecentlyPurchased,
                cancellationToken: cancellationToken);

            _progress.OnOperationCompleted("Prefill operation", timer.Elapsed);

            // Return result summary
            return new PrefillResult
            {
                Success = true,
                TotalTime = timer.Elapsed
            };
        }
        catch (OperationCanceledException)
        {
            _progress.OnLog(LogLevel.Info, "Prefill operation cancelled");
            return new PrefillResult
            {
                Success = false,
                ErrorMessage = "Prefill cancelled",
                TotalTime = timer.Elapsed
            };
        }
        catch (Exception ex)
        {
            _progress.OnError("Prefill operation failed", ex);
            return new PrefillResult
            {
                Success = false,
                ErrorMessage = ex.Message,
                TotalTime = timer.Elapsed
            };
        }
    }

    /// <summary>
    /// Prefills specific apps by their IDs
    /// </summary>
    public async Task<PrefillResult> PrefillAppsAsync(
        IEnumerable<uint> appIds,
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        ThrowIfNotInitialized();
        ThrowIfDisposed();

        // Set the apps and run prefill
        SetSelectedApps(appIds);

        return await PrefillAsync(new PrefillOptions { Force = force }, cancellationToken);
    }

    /// <summary>
    /// Disconnects from Steam
    /// </summary>
    public void Shutdown()
    {
        if (_steamManager != null && _isInitialized)
        {
            _steamManager.Shutdown();
            _isInitialized = false;
            _progress.OnLog(LogLevel.Info, "Disconnected from Steam");
        }
    }


    /// <summary>
    /// Clears the temporary cache directory to free up disk space.
    /// This is a static method that doesn't require initialization.
    /// </summary>
    /// <returns>Cache clear result with file count and total size cleared</returns>
    public static ClearCacheResult ClearCache()
    {
        var rootTempDir = new DirectoryInfo(AppConfig.TempDir).Parent;
        
        if (rootTempDir == null || !rootTempDir.Exists)
        {
            return new ClearCacheResult
            {
                Success = true,
                FileCount = 0,
                BytesCleared = 0,
                Message = "Cache directory is already empty"
            };
        }

        var tempFiles = rootTempDir.EnumerateFiles("*.*", SearchOption.AllDirectories).ToList();
        var totalBytes = tempFiles.Sum(e => e.Length);
        var fileCount = tempFiles.Count;

        if (fileCount == 0)
        {
            return new ClearCacheResult
            {
                Success = true,
                FileCount = 0,
                BytesCleared = 0,
                Message = "Cache directory is already empty"
            };
        }

        try
        {
            Directory.Delete(rootTempDir.FullName, true);
            var clearedSize = ByteSize.FromBytes(totalBytes);
            return new ClearCacheResult
            {
                Success = true,
                FileCount = fileCount,
                BytesCleared = totalBytes,
                Message = $"Cleared {fileCount} files ({clearedSize.ToDecimalString()})"
            };
        }
        catch (Exception ex)
        {
            return new ClearCacheResult
            {
                Success = false,
                FileCount = 0,
                BytesCleared = 0,
                Message = $"Failed to clear cache: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Gets information about the current cache without clearing it.
    /// </summary>
    public static ClearCacheResult GetCacheInfo()
    {
        var rootTempDir = new DirectoryInfo(AppConfig.TempDir).Parent;
        
        if (rootTempDir == null || !rootTempDir.Exists)
        {
            return new ClearCacheResult
            {
                Success = true,
                FileCount = 0,
                BytesCleared = 0,
                Message = "Cache directory is empty"
            };
        }

        var tempFiles = rootTempDir.EnumerateFiles("*.*", SearchOption.AllDirectories).ToList();
        var totalBytes = tempFiles.Sum(e => e.Length);
        var cacheSize = ByteSize.FromBytes(totalBytes);

        return new ClearCacheResult
        {
            Success = true,
            FileCount = tempFiles.Count,
            BytesCleared = totalBytes,
            Message = $"Cache contains {tempFiles.Count} files ({cacheSize.ToDecimalString()})"
        };
    }

    public void Dispose()
    {
        if (_isDisposed)
            return;

        Shutdown();
        _steamManager?.Dispose();
        _isDisposed = true;
    }

    private void ThrowIfNotInitialized()
    {
        if (!_isInitialized)
            throw new InvalidOperationException("SteamPrefillApi not initialized. Call InitializeAsync first.");
    }

    private void ThrowIfDisposed()
    {
        if (_isDisposed)
            throw new ObjectDisposedException(nameof(SteamPrefillApi));
    }
}

/// <summary>
/// Options for prefill operations
/// </summary>
public class PrefillOptions
{
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
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public int AppsUpdated { get; init; }
    public int AppsAlreadyUpToDate { get; init; }
    public int AppsFailed { get; init; }
    public long TotalBytesTransferred { get; init; }
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
/// Session storage for persisting login state between API instances
/// </summary>
public class PrefillApiSession
{
    public string? Username { get; set; }
    public string? AccessToken { get; set; }
    public uint SessionId { get; set; }
}
