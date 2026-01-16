#nullable enable

using System.Text.Json;

namespace SteamPrefill.Api;

/// <summary>
/// Command interface that uses Unix Domain Socket for IPC.
/// This is the recommended interface for production use due to its reliability
/// compared to file-based communication.
///
/// Features:
/// - Real-time bidirectional communication
/// - Reliable message delivery (no FileSystemWatcher issues)
/// - Lower latency than file-based approach
/// - Works in both Docker host and bridge network modes
/// </summary>
public sealed class SocketCommandInterface : IDisposable
{
    private readonly SocketServer _socketServer;
    private readonly SocketAuthProvider _authProvider;
    private readonly SocketProgress _progress;
    private readonly CancellationTokenSource _cts = new();
    private CancellationTokenSource? _loginCts;
    private CancellationTokenSource? _prefillCts;
    private SteamPrefillApi? _api;
    private Task? _loginTask;
    private bool _isLoggedIn;
    private bool _isLoggingIn;
    private bool _isPrefilling;
    private bool _disposed;

    // Commands allowed before login
    private static readonly HashSet<string> PreLoginCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "login",
        "status",
        "cancel-login",
        "provide-credential"
    };

    public SocketCommandInterface(string socketPath)
    {
        _progress = new SocketProgress();
        _socketServer = new SocketServer(socketPath, _progress);
        _authProvider = new SocketAuthProvider(_socketServer, _progress);
        _socketServer.OnCommand = HandleCommandAsync;

        // Wire up progress events to broadcast via socket
        _progress.SocketServer = _socketServer;
    }

    public SocketCommandInterface(int tcpPort)
    {
        _progress = new SocketProgress();
        _socketServer = new SocketServer(tcpPort, _progress);
        _authProvider = new SocketAuthProvider(_socketServer, _progress);
        _socketServer.OnCommand = HandleCommandAsync;

        _progress.SocketServer = _socketServer;
    }

    /// <summary>
    /// Start the socket server and begin accepting connections.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _progress.OnLog(LogLevel.Info, "Starting socket command interface...");

        await _socketServer.StartAsync(cancellationToken);

        // Send initial status
        await BroadcastStatusAsync("awaiting-login", "Login required before other commands can be executed");

        _progress.OnLog(LogLevel.Info, "Socket command interface started - awaiting login");
    }

    /// <summary>
    /// Stop the socket server and disconnect all clients.
    /// </summary>
    public async Task StopAsync()
    {
        _cts.Cancel();
        await _socketServer.StopAsync();
        _progress.OnLog(LogLevel.Info, "Socket command interface stopped");
    }

    private async Task<CommandResponse> HandleCommandAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        _progress.OnLog(LogLevel.Info, $"Processing command: {request.Type} (ID: {request.Id})");

        // Security check: Reject non-login commands if not authenticated
        if (!_isLoggedIn && !PreLoginCommands.Contains(request.Type))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "Authentication required. Please login first.",
                RequiresLogin = true,
                CompletedAt = DateTime.UtcNow
            };
        }

        try
        {
            return request.Type.ToLowerInvariant() switch
            {
                "login" => await HandleLoginAsync(request, cancellationToken),
                "logout" => HandleLogout(request),
                "cancel-login" => await HandleCancelLoginAsync(request),
                "cancel-prefill" => HandleCancelPrefill(request),
                "provide-credential" => HandleProvideCredential(request),
                "status" => HandleStatus(request),
                "get-owned-games" => await HandleGetOwnedGamesAsync(request, cancellationToken),
                "get-selected-apps" => HandleGetSelectedApps(request),
                "set-selected-apps" => HandleSetSelectedApps(request),
                "prefill" => await HandlePrefillAsync(request, cancellationToken),
                "clear-cache" => HandleClearCache(request),
                "get-cache-info" => HandleGetCacheInfo(request),
                "get-selected-apps-status" => await HandleGetSelectedAppsStatusAsync(request, cancellationToken),
                "check-cache-status" => await HandleCheckCacheStatusAsync(request, cancellationToken),
                "shutdown" => HandleShutdown(request),
                _ => new CommandResponse
                {
                    Id = request.Id,
                    Success = false,
                    Error = $"Unknown command type: {request.Type}",
                    CompletedAt = DateTime.UtcNow
                }
            };
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Error, $"Error handling command {request.Type}: {ex.Message}");
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = ex.Message,
                CompletedAt = DateTime.UtcNow
            };
        }
    }

    private Task<CommandResponse> HandleLoginAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        if (_isLoggedIn)
        {
            _progress.OnLog(LogLevel.Info, "Already logged in");
            return Task.FromResult(new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Message = "Already logged in",
                CompletedAt = DateTime.UtcNow
            });
        }

        if (_isLoggingIn)
        {
            _progress.OnLog(LogLevel.Info, "Login already in progress");
            return Task.FromResult(new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Message = "Login already in progress",
                CompletedAt = DateTime.UtcNow
            });
        }

        _progress.OnLog(LogLevel.Info, "Starting secure login process via socket...");
        _isLoggingIn = true;

        // Create a login-specific cancellation token
        _loginCts?.Dispose();
        _loginCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);

        // Create API with socket auth provider
        _api = new SteamPrefillApi(_authProvider, _progress);

        // Run login in background task so the command loop isn't blocked
        // This allows provide-credential commands to be processed while login is waiting
        _loginTask = Task.Run(async () =>
        {
            try
            {
                // This will trigger credential challenges via socket
                await _api.InitializeAsync(_loginCts.Token);

                _isLoggedIn = true;
                _isLoggingIn = false;
                _progress.OnLog(LogLevel.Info, "Login successful - commands now available");

                await BroadcastStatusAsync("logged-in", "Authenticated and ready for commands");
            }
            catch (OperationCanceledException)
            {
                _progress.OnLog(LogLevel.Info, "Login cancelled");
                _isLoggingIn = false;
                CleanupApiInstance();
                await BroadcastStatusAsync("awaiting-login", "Login cancelled - ready for new attempt");
            }
            catch (Exception ex)
            {
                _progress.OnLog(LogLevel.Error, $"Login failed: {ex.Message}");
                _isLoggingIn = false;
                CleanupApiInstance();
                await BroadcastStatusAsync("awaiting-login", $"Login failed: {ex.Message}");
            }
            finally
            {
                _loginCts?.Dispose();
                _loginCts = null;
            }
        }, _loginCts.Token);

        // Return immediately - login process continues in background
        return Task.FromResult(new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Login started - awaiting credentials",
            CompletedAt = DateTime.UtcNow
        });
    }

    private CommandResponse HandleLogout(CommandRequest request)
    {
        CleanupApiInstance();
        _progress.OnLog(LogLevel.Info, "Logged out");

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Logged out successfully",
            CompletedAt = DateTime.UtcNow
        };
    }

    private async Task<CommandResponse> HandleCancelLoginAsync(CommandRequest request)
    {
        _progress.OnLog(LogLevel.Info, "Cancelling login...");

        // Cancel any pending credential requests
        _authProvider.CancelPendingRequest();

        // Cancel login-specific token
        try
        {
            if (_loginCts != null)
                await _loginCts.CancelAsync();
        }
        catch { /* ignore if already disposed */ }

        CleanupApiInstance();
        await BroadcastStatusAsync("awaiting-login", "Login cancelled - ready for new attempt");

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Login cancelled",
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleCancelPrefill(CommandRequest request)
    {
        if (!_isPrefilling)
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Message = "No prefill in progress",
                CompletedAt = DateTime.UtcNow
            };
        }

        _progress.OnLog(LogLevel.Info, "Cancelling prefill...");

        try
        {
            _prefillCts?.Cancel();
        }
        catch { /* ignore */ }

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Prefill cancellation requested",
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleProvideCredential(CommandRequest request)
    {
        var challengeId = request.Parameters?.GetValueOrDefault("challengeId");
        var clientPublicKey = request.Parameters?.GetValueOrDefault("clientPublicKey");
        var encryptedCredential = request.Parameters?.GetValueOrDefault("encryptedCredential");
        var nonce = request.Parameters?.GetValueOrDefault("nonce");
        var tag = request.Parameters?.GetValueOrDefault("tag");

        if (string.IsNullOrEmpty(challengeId) || string.IsNullOrEmpty(clientPublicKey) ||
            string.IsNullOrEmpty(encryptedCredential) || string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(tag))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "Missing required credential parameters",
                CompletedAt = DateTime.UtcNow
            };
        }

        var response = new EncryptedCredentialResponse
        {
            ChallengeId = challengeId,
            ClientPublicKey = clientPublicKey,
            EncryptedCredential = encryptedCredential,
            Nonce = nonce,
            Tag = tag
        };

        _authProvider.ReceiveCredential(response);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Credential received",
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleStatus(CommandRequest request)
    {
        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = new StatusData
            {
                IsLoggedIn = _isLoggedIn,
                IsInitialized = _api?.IsInitialized ?? false
            },
            CompletedAt = DateTime.UtcNow
        };
    }

    private async Task<CommandResponse> HandleGetOwnedGamesAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        EnsureLoggedIn();
        var games = await _api!.GetOwnedGamesAsync(cancellationToken);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = games,
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleGetSelectedApps(CommandRequest request)
    {
        EnsureLoggedIn();
        var selected = _api!.GetSelectedApps();

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = selected,
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleSetSelectedApps(CommandRequest request)
    {
        EnsureLoggedIn();

        var appIdsJson = request.Parameters?.GetValueOrDefault("appIds");
        if (string.IsNullOrEmpty(appIdsJson))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "appIds parameter required",
                CompletedAt = DateTime.UtcNow
            };
        }

        var appIds = JsonSerializer.Deserialize(appIdsJson, DaemonSerializationContext.Default.ListUInt32);
        if (appIds != null && appIds.Count > 0)
        {
            _api!.SetSelectedApps(appIds);
            _progress.OnLog(LogLevel.Info, $"Set {appIds.Count} selected apps");
        }

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Apps selected",
            CompletedAt = DateTime.UtcNow
        };
    }

    private Task<CommandResponse> HandlePrefillAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        EnsureLoggedIn();

        if (_isPrefilling)
        {
            return Task.FromResult(new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "A prefill is already in progress",
                CompletedAt = DateTime.UtcNow
            });
        }

        var options = new PrefillOptions();

        if (request.Parameters != null)
        {
            if (bool.TryParse(request.Parameters.GetValueOrDefault("all"), out var all))
                options.DownloadAllOwnedGames = all;
            if (bool.TryParse(request.Parameters.GetValueOrDefault("recent"), out var recent))
                options.PrefillRecentGames = recent;
            if (bool.TryParse(request.Parameters.GetValueOrDefault("recently_purchased"), out var recentlyPurchased))
                options.PrefillRecentlyPurchased = recentlyPurchased;
            if (int.TryParse(request.Parameters.GetValueOrDefault("top"), out var top))
                options.PrefillTopGames = top;
            if (bool.TryParse(request.Parameters.GetValueOrDefault("force"), out var force))
                options.Force = force;
            if (int.TryParse(request.Parameters.GetValueOrDefault("maxConcurrency"), out var maxConcurrency) && maxConcurrency > 0)
                AppConfig.MaxConcurrencyOverride = maxConcurrency;

            // Parse operating systems
            var osParam = request.Parameters.GetValueOrDefault("os");
            if (!string.IsNullOrEmpty(osParam))
            {
                var osList = new List<OperatingSystem>();
                foreach (var os in osParam.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (OperatingSystem.TryFromValue(os.ToLowerInvariant(), out var operatingSystem))
                    {
                        osList.Add(operatingSystem);
                    }
                }
                if (osList.Count > 0)
                {
                    options.OperatingSystems = osList;
                }
            }

            // Process cached depot data
            var cachedDepotsJson = request.Parameters.GetValueOrDefault("cachedDepots");
            if (!string.IsNullOrEmpty(cachedDepotsJson))
            {
                try
                {
                    var cachedDepots = JsonSerializer.Deserialize(cachedDepotsJson, DaemonSerializationContext.Default.ListCachedDepotInput);
                    if (cachedDepots != null && cachedDepots.Count > 0)
                    {
                        _progress.OnLog(LogLevel.Info, $"Setting {cachedDepots.Count} cached depot manifests");
                        _api!.SetCachedManifests(cachedDepots.Select(d => (d.DepotId, d.ManifestId)));
                    }
                }
                catch (Exception ex)
                {
                    _progress.OnLog(LogLevel.Warning, $"Failed to process cachedDepots: {ex.Message}");
                }
            }
        }

        _prefillCts?.Dispose();
        _prefillCts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        _isPrefilling = true;

        // Run prefill in background task so the command loop isn't blocked
        // This allows cancel-prefill commands to be processed while prefill is running
        _ = Task.Run(async () =>
        {
            try
            {
                var result = await _api!.PrefillAsync(options, _prefillCts.Token);

                if (result.Success)
                {
                    _progress.OnLog(LogLevel.Info, "Prefill completed successfully");
                }
                else
                {
                    _progress.OnLog(LogLevel.Warning, $"Prefill completed with errors: {result.ErrorMessage}");
                }
            }
            catch (OperationCanceledException)
            {
                _progress.OnLog(LogLevel.Info, "Prefill cancelled by user");
            }
            catch (Exception ex)
            {
                _progress.OnLog(LogLevel.Error, $"Prefill failed: {ex.Message}");
            }
            finally
            {
                _isPrefilling = false;
                _prefillCts?.Dispose();
                _prefillCts = null;
            }
        }, _prefillCts.Token);

        // Return immediately - prefill process continues in background
        return Task.FromResult(new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Prefill started",
            CompletedAt = DateTime.UtcNow
        });
    }

    private CommandResponse HandleClearCache(CommandRequest request)
    {
        var result = SteamPrefillApi.ClearCache();
        if (result.Success && _api != null && _isLoggedIn)
        {
            _api.ClearAppInfoCache();
        }

        return new CommandResponse
        {
            Id = request.Id,
            Success = result.Success,
            Data = result,
            Message = result.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleGetCacheInfo(CommandRequest request)
    {
        var info = SteamPrefillApi.GetCacheInfo();

        return new CommandResponse
        {
            Id = request.Id,
            Success = info.Success,
            Data = info,
            Message = info.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private async Task<CommandResponse> HandleGetSelectedAppsStatusAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        EnsureLoggedIn();

        // Parse operating systems if provided
        var osParam = request.Parameters?.GetValueOrDefault("os");
        if (!string.IsNullOrEmpty(osParam))
        {
            var osList = new List<OperatingSystem>();
            foreach (var os in osParam.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (OperatingSystem.TryFromValue(os.ToLowerInvariant(), out var operatingSystem))
                {
                    osList.Add(operatingSystem);
                }
            }
            if (osList.Count > 0)
            {
                _api!.UpdateDownloadOptions(operatingSystems: osList);
            }
        }

        // Parse optional cachedDepots
        List<CachedDepotInput>? cachedDepots = null;
        var cachedDepotsJson = request.Parameters?.GetValueOrDefault("cachedDepots");
        if (!string.IsNullOrEmpty(cachedDepotsJson))
        {
            cachedDepots = JsonSerializer.Deserialize(cachedDepotsJson, DaemonSerializationContext.Default.ListCachedDepotInput);
        }

        var status = await _api!.GetSelectedAppsStatusAsync(cachedDepots, cancellationToken);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = status,
            Message = status.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private async Task<CommandResponse> HandleCheckCacheStatusAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        EnsureLoggedIn();

        var cachedDepotsJson = request.Parameters?.GetValueOrDefault("cachedDepots");
        if (string.IsNullOrEmpty(cachedDepotsJson))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = new CacheStatusResult { Apps = new List<AppCacheStatus>(), Message = "No cached depots provided" },
                Message = "No cached depots provided",
                CompletedAt = DateTime.UtcNow
            };
        }

        var cachedDepots = JsonSerializer.Deserialize(cachedDepotsJson, DaemonSerializationContext.Default.ListCachedDepotInput);
        if (cachedDepots == null || cachedDepots.Count == 0)
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = new CacheStatusResult { Apps = new List<AppCacheStatus>(), Message = "No cached depots provided" },
                Message = "No cached depots provided",
                CompletedAt = DateTime.UtcNow
            };
        }

        var status = await _api!.CheckCacheStatusAsync(cachedDepots, cancellationToken);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = status,
            Message = status.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleShutdown(CommandRequest request)
    {
        CleanupApiInstance();

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Shutdown complete",
            CompletedAt = DateTime.UtcNow
        };
    }

    private void EnsureLoggedIn()
    {
        if (!_isLoggedIn || _api == null || !_api.IsInitialized)
            throw new InvalidOperationException("Not logged in. Please login first.");
    }

    private void CleanupApiInstance()
    {
        try
        {
            _api?.Shutdown();
            _api?.Dispose();
        }
        catch { /* ignore cleanup errors */ }
        _api = null;
        _isLoggedIn = false;
        _isLoggingIn = false;
    }

    private async Task BroadcastStatusAsync(string status, string message)
    {
        var statusEvent = new AuthStateEvent(status, message);
        await _socketServer.BroadcastAuthStateAsync(statusEvent);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _cts.Cancel();
        _loginCts?.Dispose();
        _prefillCts?.Dispose();
        _cts.Dispose();
        _api?.Dispose();
        _authProvider.Dispose();
        _socketServer.DisposeAsync().AsTask().Wait();
        _disposed = true;

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Progress implementation that broadcasts updates via socket.
    /// </summary>
    private sealed class SocketProgress : IPrefillProgress
    {
        public SocketServer? SocketServer { get; set; }
        private DateTime _lastProgressBroadcast = DateTime.MinValue;
        private static readonly TimeSpan BroadcastThrottle = TimeSpan.FromMilliseconds(250);

        public void OnLog(LogLevel level, string message)
        {
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

        public void OnOperationStarted(string operationName)
            => OnLog(LogLevel.Info, $"Starting: {operationName}");

        public void OnOperationCompleted(string operationName, TimeSpan elapsed)
            => OnLog(LogLevel.Info, $"Completed: {operationName} ({elapsed.TotalSeconds:F2}s)");

        public void OnAppStarted(AppDownloadInfo app)
        {
            OnLog(LogLevel.Info, $"Downloading: {app.Name} ({app.AppId})");
            BroadcastProgress(new PrefillProgressUpdate
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
            var now = DateTime.UtcNow;
            if (now - _lastProgressBroadcast < BroadcastThrottle)
                return;

            _lastProgressBroadcast = now;

            // Log progress to console
            var downloadedStr = FormatBytes(progress.BytesDownloaded);
            var totalStr = FormatBytes(progress.TotalBytes);
            var speedStr = FormatBytes((long)progress.BytesPerSecond) + "/s";
            OnLog(LogLevel.Info, $"{progress.AppName}: {progress.PercentComplete:F1}% - {speedStr} - {downloadedStr} / {totalStr}");

            BroadcastProgress(new PrefillProgressUpdate
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

        private static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            double size = bytes;
            while (size >= 1024 && order < sizes.Length - 1)
            {
                order++;
                size /= 1024;
            }
            return $"{size:F2} {sizes[order]}";
        }

        public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result)
        {
            OnLog(LogLevel.Info, $"Completed: {app.Name} - {result}");
            var bytesDownloaded = result == AppDownloadResult.Success ? app.TotalBytes : 0;

            // Use distinct state for cached apps so frontend can show blue animation
            var state = result == AppDownloadResult.AlreadyUpToDate ? "already_cached" : "app_completed";

            BroadcastProgress(new PrefillProgressUpdate
            {
                State = state,
                CurrentAppId = app.AppId,
                CurrentAppName = app.Name,
                TotalBytes = app.TotalBytes,
                BytesDownloaded = bytesDownloaded,
                Result = result.ToString(),
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
            BroadcastProgress(new PrefillProgressUpdate
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
        }

        public void OnError(string message, Exception? exception = null)
        {
            OnLog(LogLevel.Error, message);
            BroadcastProgress(new PrefillProgressUpdate
            {
                State = "error",
                ErrorMessage = message,
                UpdatedAt = DateTime.UtcNow
            });
        }

        private void BroadcastProgress(PrefillProgressUpdate update)
        {
            if (SocketServer == null) return;

            var progressEvent = new ProgressEvent(update);
            _ = SocketServer.BroadcastProgressAsync(progressEvent);
        }
    }
}
