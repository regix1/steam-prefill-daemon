#nullable enable

using System.Text.Json;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;

namespace SteamPrefill.Api;

/// <summary>
/// SignalR client for daemon-to-API communication.
/// Replaces file-based communication with direct SignalR messaging.
/// 
/// The daemon connects to the API's SignalR hub and:
/// - Receives commands from the API
/// - Sends progress updates back to the API
/// - Handles credential exchange for Steam login
/// </summary>
public sealed class SignalRDaemonClient : IAsyncDisposable
{
    private readonly HubConnection _connection;
    private readonly string _sessionId;
    private readonly IPrefillProgress _progress;
    private readonly SemaphoreSlim _commandLock = new(1, 1);
    private SteamPrefillApi? _api;
    private bool _isLoggedIn;
    private bool _isPrefilling;
    private CancellationTokenSource? _prefillCts;
    
    // For credential exchange
    private TaskCompletionSource<(CredentialChallenge challenge, string credential)>? _pendingCredential;
    private readonly SemaphoreSlim _credentialLock = new(1, 1);

    public bool IsConnected => _connection.State == HubConnectionState.Connected;
    public string SessionId => _sessionId;

    public SignalRDaemonClient(string apiUrl, string sessionId, IPrefillProgress progress)
    {
        _sessionId = sessionId;
        _progress = progress;

        var hubUrl = apiUrl.TrimEnd('/') + "/hubs/prefill-daemon";
        
        _progress.OnLog(LogLevel.Info, $"Connecting to API hub: {hubUrl}");

        _connection = new HubConnectionBuilder()
            .WithUrl(hubUrl, options =>
            {
                // Pass session ID as query parameter for authentication
                options.Headers.Add("X-Session-Id", sessionId);
            })
            .AddJsonProtocol(options =>
            {
                // Use source-generated JSON serialization for AOT/trimming compatibility
                options.PayloadSerializerOptions.TypeInfoResolver = DaemonSerializationContext.Default;
            })
            .WithAutomaticReconnect(new[] {
                TimeSpan.Zero,
                TimeSpan.FromSeconds(2),
                TimeSpan.FromSeconds(5),
                TimeSpan.FromSeconds(10),
                TimeSpan.FromSeconds(30)
            })
            .Build();

        // Setup event handlers
        _connection.Closed += OnConnectionClosed;
        _connection.Reconnecting += OnReconnecting;
        _connection.Reconnected += OnReconnected;

        // Register handlers for commands from the API
        RegisterCommandHandlers();
    }

    private void RegisterCommandHandlers()
    {
        // Command handlers - these are called by the API to execute operations on the daemon
        _connection.On<string>("ExecuteLogin", async (commandId) => await HandleLoginCommandAsync(commandId));
        _connection.On<string>("ExecuteLogout", async (commandId) => await HandleLogoutCommandAsync(commandId));
        _connection.On<string>("ExecuteGetOwnedGames", async (commandId) => await HandleGetOwnedGamesCommandAsync(commandId));
        _connection.On<string, string>("ExecuteSetSelectedApps", async (commandId, appIdsJson) => await HandleSetSelectedAppsCommandAsync(commandId, appIdsJson));
        _connection.On<string>("ExecuteGetSelectedApps", async (commandId) => await HandleGetSelectedAppsCommandAsync(commandId));
        _connection.On<string, string>("ExecutePrefill", async (commandId, optionsJson) => await HandlePrefillCommandAsync(commandId, optionsJson));
        _connection.On<string, string>("ExecuteGetSelectedAppsStatus", async (commandId, optionsJson) => await HandleGetSelectedAppsStatusCommandAsync(commandId, optionsJson));
        _connection.On<string>("ExecuteGetStatus", async (commandId) => await HandleGetStatusCommandAsync(commandId));
        _connection.On<string>("ExecuteClearCache", async (commandId) => await HandleClearCacheCommandAsync(commandId));
        _connection.On<string>("ExecuteGetCacheInfo", async (commandId) => await HandleGetCacheInfoCommandAsync(commandId));
        _connection.On<string>("ExecuteClearCachedManifests", async (commandId) => await HandleClearCachedManifestsCommandAsync(commandId));
        
        // Credential exchange handlers
        _connection.On<CredentialChallenge, string>("ProvideCredential", OnCredentialReceived);
        
        // Cancel handlers
        _connection.On("CancelLogin", OnCancelLogin);
        _connection.On("CancelPrefill", OnCancelPrefill);
    }

    #region Command Handlers

    private async Task HandleLoginCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received login command: {commandId}");
        var response = await LoginAsync();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task HandleLogoutCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received logout command: {commandId}");
        Logout();
        await SendCommandResponseAsync(new CommandResponse { Id = commandId, Success = true, Message = "Logged out" });
    }

    private async Task HandleGetOwnedGamesCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received get-owned-games command: {commandId}");
        var response = await GetOwnedGamesAsync();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task HandleSetSelectedAppsCommandAsync(string commandId, string appIdsJson)
    {
        _progress.OnLog(LogLevel.Info, $"Received set-selected-apps command: {commandId}");
        try
        {
            var appIds = JsonSerializer.Deserialize(appIdsJson, DaemonSerializationContext.Default.ListUInt32) ?? new List<uint>();
            var response = SetSelectedApps(appIds);
            response.Id = commandId;
            await SendCommandResponseAsync(response);
        }
        catch (Exception ex)
        {
            await SendCommandResponseAsync(new CommandResponse { Id = commandId, Success = false, Error = ex.Message });
        }
    }

    private async Task HandleGetSelectedAppsCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received get-selected-apps command: {commandId}");
        var response = GetSelectedApps();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task HandlePrefillCommandAsync(string commandId, string optionsJson)
    {
        _progress.OnLog(LogLevel.Info, $"Received prefill command: {commandId}");
        try
        {
            var options = JsonSerializer.Deserialize(optionsJson, DaemonSerializationContext.Default.PrefillCommandOptions) ?? new PrefillCommandOptions();
            var response = await PrefillAsync(
                all: options.All,
                recent: options.Recent,
                force: options.Force,
                operatingSystems: options.OperatingSystems,
                cachedDepots: options.CachedDepots);
            response.Id = commandId;
            await SendCommandResponseAsync(response);
        }
        catch (Exception ex)
        {
            await SendCommandResponseAsync(new CommandResponse { Id = commandId, Success = false, Error = ex.Message });
        }
    }

    private async Task HandleGetSelectedAppsStatusCommandAsync(string commandId, string optionsJson)
    {
        _progress.OnLog(LogLevel.Info, $"Received get-selected-apps-status command: {commandId}");
        try
        {
            var options = JsonSerializer.Deserialize(optionsJson, DaemonSerializationContext.Default.GetStatusCommandOptions) ?? new GetStatusCommandOptions();
            var response = await GetSelectedAppsStatusAsync(options.OperatingSystems, options.CachedDepots);
            response.Id = commandId;
            await SendCommandResponseAsync(response);
        }
        catch (Exception ex)
        {
            await SendCommandResponseAsync(new CommandResponse { Id = commandId, Success = false, Error = ex.Message });
        }
    }

    private async Task HandleGetStatusCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received get-status command: {commandId}");
        var response = GetStatus();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task HandleClearCacheCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received clear-cache command: {commandId}");
        var response = ClearCache();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task HandleGetCacheInfoCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received get-cache-info command: {commandId}");
        var response = GetCacheInfo();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task HandleClearCachedManifestsCommandAsync(string commandId)
    {
        _progress.OnLog(LogLevel.Info, $"Received clear-cached-manifests command: {commandId}");
        var response = ClearCachedManifests();
        response.Id = commandId;
        await SendCommandResponseAsync(response);
    }

    private async Task SendCommandResponseAsync(CommandResponse response)
    {
        if (_connection.State != HubConnectionState.Connected)
        {
            _progress.OnLog(LogLevel.Warning, $"Cannot send response {response.Id} - not connected");
            return;
        }

        try
        {
            response.CompletedAt = DateTime.UtcNow;
            await _connection.InvokeAsync("CommandResponse", _sessionId, response);
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Failed to send command response: {ex.Message}");
        }
    }

    #endregion

    /// <summary>
    /// Connects to the API hub and registers this daemon session
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await _connection.StartAsync(cancellationToken);
            _progress.OnLog(LogLevel.Info, "Connected to API hub");

            // Register this daemon with the API
            await _connection.InvokeAsync("DaemonConnected", _sessionId, cancellationToken);
            _progress.OnLog(LogLevel.Info, $"Registered daemon session: {_sessionId}");
        }
        catch (Exception ex)
        {
            _progress.OnError($"Failed to connect to API hub: {ex.Message}", ex);
            throw;
        }
    }

    private async Task OnConnectionClosed(Exception? error)
    {
        if (error != null)
        {
            _progress.OnLog(LogLevel.Warning, $"Connection closed with error: {error.Message}");
        }
        else
        {
            _progress.OnLog(LogLevel.Info, "Connection closed");
        }
        await Task.CompletedTask;
    }

    private async Task OnReconnecting(Exception? error)
    {
        _progress.OnLog(LogLevel.Warning, $"Reconnecting to API hub... (error: {error?.Message ?? "none"})");
        await Task.CompletedTask;
    }

    private async Task OnReconnected(string? connectionId)
    {
        _progress.OnLog(LogLevel.Info, $"Reconnected to API hub (connection: {connectionId})");
        
        // Re-register session after reconnect
        try
        {
            await _connection.InvokeAsync("DaemonConnected", _sessionId);
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Failed to re-register session: {ex.Message}");
        }
    }

    #region Progress Reporting

    /// <summary>
    /// Sends a progress update to the API
    /// </summary>
    public async Task ReportProgressAsync(PrefillProgressUpdate progress)
    {
        if (_connection.State != HubConnectionState.Connected)
            return;

        try
        {
            await _connection.InvokeAsync("ReportProgress", _sessionId, progress);
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Failed to report progress: {ex.Message}");
        }
    }

    /// <summary>
    /// Reports daemon status to the API
    /// </summary>
    public async Task ReportStatusAsync(string status, string message)
    {
        if (_connection.State != HubConnectionState.Connected)
            return;

        try
        {
            var statusUpdate = new DaemonStatus
            {
                Type = "status-update",
                Status = status,
                Message = message,
                Timestamp = DateTime.UtcNow
            };
            await _connection.InvokeAsync("ReportStatus", _sessionId, statusUpdate);
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Failed to report status: {ex.Message}");
        }
    }

    #endregion

    #region Command Execution

    /// <summary>
    /// Executes the login command
    /// </summary>
    public async Task<CommandResponse> LoginAsync(CancellationToken cancellationToken = default)
    {
        await _commandLock.WaitAsync(cancellationToken);
        try
        {
            if (_isLoggedIn)
            {
                return new CommandResponse { Success = true, Message = "Already logged in" };
            }

            _progress.OnLog(LogLevel.Info, "Starting login process...");
            await ReportStatusAsync("logging-in", "Starting login process");

            // Create API with SignalR auth provider
            var authProvider = new SignalRAuthProvider(this, _progress);
            _api = new SteamPrefillApi(authProvider, new SignalRProgress(this, _progress));

            try
            {
                await _api.InitializeAsync(cancellationToken);
                _isLoggedIn = true;
                _progress.OnLog(LogLevel.Info, "Login successful");
                await ReportStatusAsync("logged-in", "Authentication successful");
                return new CommandResponse { Success = true, Message = "Login successful" };
            }
            catch (OperationCanceledException)
            {
                _api?.Shutdown();
                _api?.Dispose();
                _api = null;
                await ReportStatusAsync("awaiting-login", "Login cancelled");
                return new CommandResponse { Success = false, Error = "Login cancelled" };
            }
            catch (Exception ex)
            {
                _api?.Shutdown();
                _api?.Dispose();
                _api = null;
                _progress.OnError($"Login failed: {ex.Message}", ex);
                await ReportStatusAsync("awaiting-login", $"Login failed: {ex.Message}");
                return new CommandResponse { Success = false, Error = ex.Message };
            }
        }
        finally
        {
            _commandLock.Release();
        }
    }

    /// <summary>
    /// Gets owned games
    /// </summary>
    public async Task<CommandResponse> GetOwnedGamesAsync(CancellationToken cancellationToken = default)
    {
        EnsureLoggedIn();
        var games = await _api!.GetOwnedGamesAsync(cancellationToken);
        return new CommandResponse { Success = true, Data = games };
    }

    /// <summary>
    /// Sets selected apps for prefill
    /// </summary>
    public CommandResponse SetSelectedApps(List<uint> appIds)
    {
        EnsureLoggedIn();
        _api!.SetSelectedApps(appIds);
        _progress.OnLog(LogLevel.Info, $"Set {appIds.Count} apps for prefill");
        return new CommandResponse { Success = true, Message = $"Set {appIds.Count} apps" };
    }

    /// <summary>
    /// Gets the current selected apps
    /// </summary>
    public CommandResponse GetSelectedApps()
    {
        EnsureLoggedIn();
        var apps = _api!.GetSelectedApps();
        return new CommandResponse { Success = true, Data = apps };
    }

    /// <summary>
    /// Executes a prefill operation
    /// </summary>
    public async Task<CommandResponse> PrefillAsync(
        bool all = false,
        bool recent = false,
        bool force = false,
        List<string>? operatingSystems = null,
        List<CachedDepotInput>? cachedDepots = null,
        CancellationToken cancellationToken = default)
    {
        await _commandLock.WaitAsync(cancellationToken);
        try
        {
            EnsureLoggedIn();

            if (_isPrefilling)
            {
                return new CommandResponse { Success = false, Error = "A prefill is already in progress" };
            }

            // Set cached manifests if provided
            if (cachedDepots != null && cachedDepots.Count > 0)
            {
                _progress.OnLog(LogLevel.Info, $"Setting {cachedDepots.Count} cached depot manifests from API");
                _api!.SetCachedManifests(cachedDepots.Select(d => (d.DepotId, d.ManifestId)));
            }

            var options = new PrefillOptions
            {
                DownloadAllOwnedGames = all,
                PrefillRecentGames = recent,
                Force = force
            };

            // Parse operating systems
            if (operatingSystems != null && operatingSystems.Count > 0)
            {
                var osList = new List<OperatingSystem>();
                foreach (var os in operatingSystems)
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

            _prefillCts?.Dispose();
            _prefillCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _isPrefilling = true;

            try
            {
                _progress.OnLog(LogLevel.Info, "Starting prefill operation");
                var result = await _api!.PrefillAsync(options, _prefillCts.Token);
                return new CommandResponse { Success = result.Success, Data = result, Message = result.Success ? "Prefill completed" : result.ErrorMessage };
            }
            catch (OperationCanceledException)
            {
                _progress.OnLog(LogLevel.Info, "Prefill cancelled");
                return new CommandResponse { Success = false, Error = "Prefill cancelled by user" };
            }
            finally
            {
                _isPrefilling = false;
                _prefillCts?.Dispose();
                _prefillCts = null;
            }
        }
        finally
        {
            _commandLock.Release();
        }
    }

    /// <summary>
    /// Gets selected apps status with sizes
    /// </summary>
    public async Task<CommandResponse> GetSelectedAppsStatusAsync(
        List<string>? operatingSystems = null,
        List<CachedDepotInput>? cachedDepots = null,
        CancellationToken cancellationToken = default)
    {
        EnsureLoggedIn();

        // Apply operating systems if provided
        if (operatingSystems != null && operatingSystems.Count > 0)
        {
            var osList = new List<OperatingSystem>();
            foreach (var os in operatingSystems)
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

        var status = await _api!.GetSelectedAppsStatusAsync(cachedDepots, cancellationToken);
        return new CommandResponse { Success = true, Data = status, Message = status.Message };
    }

    /// <summary>
    /// Clears the daemon's temporary cache
    /// </summary>
    public CommandResponse ClearCache()
    {
        var result = SteamPrefillApi.ClearCache();
        if (result.Success && _api != null && _isLoggedIn)
        {
            _api.ClearAppInfoCache();
        }
        return new CommandResponse { Success = result.Success, Data = result, Message = result.Message };
    }

    /// <summary>
    /// Gets cache info
    /// </summary>
    public CommandResponse GetCacheInfo()
    {
        var info = SteamPrefillApi.GetCacheInfo();
        return new CommandResponse { Success = info.Success, Data = info, Message = info.Message };
    }

    /// <summary>
    /// Clears cached manifests
    /// </summary>
    public CommandResponse ClearCachedManifests()
    {
        if (_api != null && _isLoggedIn)
        {
            var count = _api.ClearCachedManifests();
            return new CommandResponse { Success = true, Data = new { ClearedCount = count }, Message = $"Cleared {count} cached manifests" };
        }
        return new CommandResponse { Success = false, Error = "Not logged in" };
    }

    /// <summary>
    /// Gets current status
    /// </summary>
    public CommandResponse GetStatus()
    {
        return new CommandResponse
        {
            Success = true,
            Data = new StatusData
            {
                IsLoggedIn = _isLoggedIn,
                IsInitialized = _api?.IsInitialized ?? false
            }
        };
    }

    /// <summary>
    /// Logs out and cleans up
    /// </summary>
    public void Logout()
    {
        _api?.Shutdown();
        _api?.Dispose();
        _api = null;
        _isLoggedIn = false;
        _progress.OnLog(LogLevel.Info, "Logged out");
    }

    private void EnsureLoggedIn()
    {
        if (!_isLoggedIn || _api == null || !_api.IsInitialized)
            throw new InvalidOperationException("Not logged in. Please login first.");
    }

    #endregion

    #region Credential Exchange

    /// <summary>
    /// Requests a credential from the API via SignalR
    /// </summary>
    internal async Task<string> RequestCredentialAsync(string credentialType, string? email = null, CancellationToken cancellationToken = default)
    {
        await _credentialLock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<(CredentialChallenge, string)>();

            // Request credential challenge from API
            _progress.OnLog(LogLevel.Info, $"Requesting {credentialType} credential from API...");
            
            var challenge = await _connection.InvokeAsync<CredentialChallenge?>(
                "RequestCredential", 
                _sessionId, 
                credentialType, 
                email, 
                cancellationToken);

            if (challenge == null)
            {
                throw new InvalidOperationException($"Failed to get credential challenge for {credentialType}");
            }

            // Wait for credential to be provided via ProvideCredential handler
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var reg = linkedCts.Token.Register(() => _pendingCredential.TrySetCanceled());

            try
            {
                var (_, credential) = await _pendingCredential.Task;
                return credential;
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                throw new TimeoutException($"Timeout waiting for {credentialType} credential");
            }
        }
        finally
        {
            _pendingCredential = null;
            _credentialLock.Release();
        }
    }

    /// <summary>
    /// Called when the API provides a credential (via SignalR)
    /// </summary>
    private void OnCredentialReceived(CredentialChallenge challenge, string encryptedCredential)
    {
        _progress.OnLog(LogLevel.Debug, $"Received {challenge.CredentialType} credential from API");
        
        // The credential comes encrypted, decrypt it
        var response = new EncryptedCredentialResponse
        {
            ChallengeId = challenge.ChallengeId,
            EncryptedCredential = encryptedCredential
            // Note: The API should send the full encrypted response
        };
        
        // For now, assume the API sends the decrypted credential directly over the secure SignalR connection
        // In production, you'd want to maintain the ECDH encryption even over SignalR
        _pendingCredential?.TrySetResult((challenge, encryptedCredential));
    }

    private void OnCancelLogin()
    {
        _progress.OnLog(LogLevel.Info, "Cancel login received from API");
        _pendingCredential?.TrySetCanceled();
    }

    private void OnCancelPrefill()
    {
        _progress.OnLog(LogLevel.Info, "Cancel prefill received from API");
        try
        {
            _prefillCts?.Cancel();
        }
        catch { /* ignore */ }
    }

    #endregion

    public async ValueTask DisposeAsync()
    {
        Logout();
        _prefillCts?.Dispose();
        _commandLock.Dispose();
        _credentialLock.Dispose();
        await _connection.DisposeAsync();
    }
}

/// <summary>
/// SignalR-based auth provider for daemon mode
/// </summary>
internal sealed class SignalRAuthProvider : ISteamAuthProvider
{
    private readonly SignalRDaemonClient _client;
    private readonly IPrefillProgress _progress;

    public SignalRAuthProvider(SignalRDaemonClient client, IPrefillProgress progress)
    {
        _client = client;
        _progress = progress;
    }

    public Task<string> GetUsernameAsync(CancellationToken cancellationToken = default)
        => _client.RequestCredentialAsync("username", null, cancellationToken);

    public Task<string> GetPasswordAsync(CancellationToken cancellationToken = default)
        => _client.RequestCredentialAsync("password", null, cancellationToken);

    public Task<string> GetSteamGuardCodeAsync(string email, CancellationToken cancellationToken = default)
        => _client.RequestCredentialAsync("steamguard", email, cancellationToken);

    public Task<string> GetTwoFactorCodeAsync(CancellationToken cancellationToken = default)
        => _client.RequestCredentialAsync("2fa", null, cancellationToken);

    public async Task GetDeviceConfirmationAsync(CancellationToken cancellationToken = default)
    {
        await _client.RequestCredentialAsync("device-confirmation", null, cancellationToken);
    }

    public Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
    {
        _progress.OnLog(LogLevel.Warning, message);
        return _client.RequestCredentialAsync("password", null, cancellationToken);
    }

    public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(null);
}

/// <summary>
/// Progress reporter that sends updates via SignalR
/// </summary>
internal sealed class SignalRProgress : IPrefillProgress
{
    private readonly SignalRDaemonClient _client;
    private readonly IPrefillProgress _consoleProgress;
    private DateTime _lastProgressUpdate = DateTime.MinValue;
    private static readonly TimeSpan ProgressThrottle = TimeSpan.FromMilliseconds(250);

    public SignalRProgress(SignalRDaemonClient client, IPrefillProgress consoleProgress)
    {
        _client = client;
        _consoleProgress = consoleProgress;
    }

    public void OnLog(LogLevel level, string message)
    {
        _consoleProgress.OnLog(level, message);
        
        // Send important messages as progress updates
        if (level == LogLevel.Info && IsProgressMessage(message))
        {
            var state = GetStateFromMessage(message);
            _ = _client.ReportProgressAsync(new PrefillProgressUpdate
            {
                State = state,
                Message = message,
                UpdatedAt = DateTime.UtcNow
            });
        }
    }

    private static bool IsProgressMessage(string message)
    {
        return message.Contains("Loading metadata") ||
               message.Contains("Metadata loaded") ||
               message.Contains("Starting prefill of") ||
               message.Contains("apps selected") ||
               message.Contains("Starting login") ||
               message.Contains("Login successful");
    }

    private static string GetStateFromMessage(string message)
    {
        if (message.Contains("Loading metadata")) return "loading-metadata";
        if (message.Contains("Metadata loaded")) return "metadata-loaded";
        if (message.Contains("Starting prefill")) return "starting";
        if (message.Contains("Login successful")) return "logged-in";
        return "preparing";
    }

    public void OnOperationStarted(string operationName)
    {
        _consoleProgress.OnOperationStarted(operationName);
    }

    public void OnOperationCompleted(string operationName, TimeSpan elapsed)
    {
        _consoleProgress.OnOperationCompleted(operationName, elapsed);
    }

    public void OnAppStarted(AppDownloadInfo app)
    {
        _consoleProgress.OnAppStarted(app);
        
        _ = _client.ReportProgressAsync(new PrefillProgressUpdate
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
        _consoleProgress.OnDownloadProgress(progress);
        
        // Throttle progress updates
        var now = DateTime.UtcNow;
        if (now - _lastProgressUpdate < ProgressThrottle)
            return;
        _lastProgressUpdate = now;

        _ = _client.ReportProgressAsync(new PrefillProgressUpdate
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
        _consoleProgress.OnAppCompleted(app, result);

        var bytesDownloaded = result == AppDownloadResult.Success ? app.TotalBytes : 0;

        _ = _client.ReportProgressAsync(new PrefillProgressUpdate
        {
            State = "app_completed",
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
        _consoleProgress.OnPrefillCompleted(summary);

        _ = _client.ReportProgressAsync(new PrefillProgressUpdate
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
        _consoleProgress.OnError(message, exception);

        _ = _client.ReportProgressAsync(new PrefillProgressUpdate
        {
            State = "error",
            ErrorMessage = message,
            UpdatedAt = DateTime.UtcNow
        });
    }
}
