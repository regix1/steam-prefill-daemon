#nullable enable

using System.Text.Json;
using System.Text.Json.Serialization;

namespace SteamPrefill.Api;

/// <summary>
/// Secure file-based command interface for controlling SteamPrefill from external processes.
/// This is ideal for Docker containers where you can mount a volume for command/response files.
///
/// Security features:
/// - Login REQUIRED before any other commands can be executed
/// - Encrypted credential exchange (never plain text)
/// - Commands rejected if not authenticated
///
/// Usage:
/// 1. Write a "login" command JSON file to the commands directory
/// 2. Daemon responds with an encrypted credential challenge
/// 3. Client encrypts credentials and sends back encrypted response
/// 4. Once logged in, other commands become available
/// </summary>
public sealed class SecureFileCommandInterface : IDisposable
{
    private readonly string _commandsDir;
    private readonly string _responsesDir;
    private readonly SecureDaemonAuthProvider _authProvider;
    private readonly IPrefillProgress _progress;
    private readonly CancellationTokenSource _cts = new();
    private FileSystemWatcher? _watcher;
    private SteamPrefillApi? _api;
    private bool _isRunning;
    private bool _isDisposed;
    private bool _isLoggedIn;
    private readonly SemaphoreSlim _commandLock = new(1, 1);

    // Commands that are allowed before login
    private static readonly HashSet<string> PreLoginCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "login",
        "status"
    };

    public SecureFileCommandInterface(
        string commandsDir,
        string responsesDir,
        IPrefillProgress? progress = null)
    {
        _commandsDir = commandsDir;
        _responsesDir = responsesDir;
        _progress = progress ?? NullProgress.Instance;

        // Create secure auth provider
        _authProvider = new SecureDaemonAuthProvider(commandsDir, responsesDir, _progress);

        // Ensure directories exist
        Directory.CreateDirectory(_commandsDir);
        Directory.CreateDirectory(_responsesDir);
    }

    /// <summary>
    /// Start watching for command files
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_isRunning)
            return;

        _progress.OnLog(LogLevel.Info, $"Starting secure file command interface. Watching: {_commandsDir}");

        // Write initial status file indicating login is required
        await WriteStatusAsync("awaiting-login", "Login required before other commands can be executed");

        // Process any existing command files first
        foreach (var file in Directory.GetFiles(_commandsDir, "*.json").OrderBy(f => File.GetCreationTimeUtc(f)))
        {
            // Skip credential files - handled by auth provider
            var fileName = Path.GetFileName(file);
            if (fileName.StartsWith("cred_", StringComparison.OrdinalIgnoreCase))
                continue;

            // Skip encrypted credential responses - handled by auth provider
            try
            {
                var content = await File.ReadAllTextAsync(file, cancellationToken);
                if (content.Contains("encryptedCredential", StringComparison.OrdinalIgnoreCase))
                    continue;
            }
            catch (FileNotFoundException)
            {
                continue; // File was deleted by auth provider
            }

            await ProcessCommandFileAsync(file);
        }

        // Start watching for new files
        _watcher = new FileSystemWatcher(_commandsDir, "*.json")
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };

        _watcher.Created += async (sender, e) =>
        {
            try
            {
                // Skip credential files - handled by auth provider
                var fileName = Path.GetFileName(e.FullPath);
                if (fileName.StartsWith("cred_", StringComparison.OrdinalIgnoreCase))
                    return;

                await Task.Delay(100, _cts.Token); // Small delay to ensure file is fully written

                // Skip encrypted credential responses - handled by auth provider
                string content;
                try
                {
                    content = await File.ReadAllTextAsync(e.FullPath, _cts.Token);
                }
                catch (FileNotFoundException)
                {
                    return; // File was deleted by auth provider
                }

                if (content.Contains("encryptedCredential", StringComparison.OrdinalIgnoreCase))
                    return;

                await ProcessCommandFileAsync(e.FullPath);
            }
            catch (OperationCanceledException)
            {
                // Expected during shutdown
            }
            catch (Exception ex)
            {
                _progress.OnError($"Error processing command file: {ex.Message}");
            }
        };

        _isRunning = true;
        _progress.OnLog(LogLevel.Info, "Secure file command interface started - awaiting login");
    }

    /// <summary>
    /// Stop watching for command files
    /// </summary>
    public void Stop()
    {
        _cts.Cancel();
        _watcher?.Dispose();
        _watcher = null;
        _isRunning = false;
        _progress.OnLog(LogLevel.Info, "File command interface stopped");
    }

    private async Task ProcessCommandFileAsync(string filePath)
    {
        await _commandLock.WaitAsync(_cts.Token);
        try
        {
            CommandRequest? command = null;
            CommandResponse response;

            try
            {
                // Read and parse command
                var json = await File.ReadAllTextAsync(filePath, _cts.Token);
                command = JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.CommandRequest);

                if (command == null)
                {
                    throw new InvalidOperationException("Invalid command format");
                }

                _progress.OnLog(LogLevel.Info, $"Processing command: {command.Type} (ID: {command.Id})");

                // Security check: Reject non-login commands if not authenticated
                if (!_isLoggedIn && !PreLoginCommands.Contains(command.Type))
                {
                    response = new CommandResponse
                    {
                        Id = command.Id,
                        Success = false,
                        Error = "Authentication required. Please login first.",
                        RequiresLogin = true,
                        CompletedAt = DateTime.UtcNow
                    };
                }
                else
                {
                    // Execute command
                    response = await ExecuteCommandAsync(command);
                }
            }
            catch (Exception ex)
            {
                _progress.OnError($"Error processing command file: {filePath}", ex);
                response = new CommandResponse
                {
                    Id = command?.Id ?? Guid.NewGuid().ToString(),
                    Success = false,
                    Error = ex.Message,
                    CompletedAt = DateTime.UtcNow
                };
            }
            finally
            {
                // Delete the command file after processing
                try { File.Delete(filePath); } catch { /* ignore */ }
            }

            // Write response
            await WriteResponseAsync(response);
        }
        finally
        {
            _commandLock.Release();
        }
    }

    private async Task<CommandResponse> ExecuteCommandAsync(CommandRequest command)
    {
        var response = new CommandResponse
        {
            Id = command.Id,
            CompletedAt = DateTime.UtcNow
        };

        try
        {
            switch (command.Type.ToLowerInvariant())
            {
                case "login":
                    await HandleLoginAsync();
                    response.Success = true;
                    response.Message = "Login successful";
                    break;

                case "logout":
                    HandleLogout();
                    response.Success = true;
                    response.Message = "Logged out successfully";
                    break;

                case "get-owned-games":
                    var games = await HandleGetOwnedGamesAsync();
                    response.Success = true;
                    response.Data = games;
                    break;

                case "get-selected-apps":
                    var selected = HandleGetSelectedApps();
                    response.Success = true;
                    response.Data = selected;
                    break;

                case "set-selected-apps":
                    HandleSetSelectedApps(command);
                    response.Success = true;
                    response.Message = "Apps selected";
                    break;

                case "prefill":
                    var result = await HandlePrefillAsync(command);
                    response.Success = result.Success;
                    response.Data = result;
                    response.Message = result.Success ? "Prefill completed" : result.ErrorMessage;
                    break;

                case "status":
                    response.Success = true;
                    response.Data = new
                    {
                        IsLoggedIn = _isLoggedIn,
                        IsInitialized = _api?.IsInitialized ?? false
                    };
                    break;

                case "shutdown":
                    HandleShutdown();
                    response.Success = true;
                    response.Message = "Shutdown complete";
                    break;

                default:
                    response.Success = false;
                    response.Error = $"Unknown command type: {command.Type}";
                    break;
            }
        }
        catch (Exception ex)
        {
            response.Success = false;
            response.Error = ex.Message;
        }

        response.CompletedAt = DateTime.UtcNow;
        return response;
    }

    private async Task HandleLoginAsync()
    {
        if (_isLoggedIn)
        {
            _progress.OnLog(LogLevel.Info, "Already logged in");
            return;
        }

        _progress.OnLog(LogLevel.Info, "Starting secure login process...");

        // Create API with secure auth provider
        _api = new SteamPrefillApi(_authProvider, _progress);

        // This will trigger the secure credential exchange
        await _api.InitializeAsync(_cts.Token);

        _isLoggedIn = true;
        _progress.OnLog(LogLevel.Info, "Login successful - commands now available");

        // Update status file
        await WriteStatusAsync("logged-in", "Authenticated and ready for commands");
    }

    private void HandleLogout()
    {
        _api?.Shutdown();
        _api?.Dispose();
        _api = null;
        _isLoggedIn = false;
        _progress.OnLog(LogLevel.Info, "Logged out");
    }

    private async Task<List<OwnedGame>> HandleGetOwnedGamesAsync()
    {
        EnsureLoggedIn();
        return await _api!.GetOwnedGamesAsync(_cts.Token);
    }

    private List<uint> HandleGetSelectedApps()
    {
        EnsureLoggedIn();
        return _api!.GetSelectedApps();
    }

    private void HandleSetSelectedApps(CommandRequest command)
    {
        EnsureLoggedIn();

        var appIdsJson = command.Parameters?.GetValueOrDefault("appIds");
        if (string.IsNullOrEmpty(appIdsJson))
            throw new ArgumentException("appIds parameter required");

        var appIds = JsonSerializer.Deserialize(appIdsJson, DaemonSerializationContext.Default.ListUInt32);
        if (appIds != null)
        {
            _api!.SetSelectedApps(appIds);
        }
    }

    private async Task<PrefillResult> HandlePrefillAsync(CommandRequest command)
    {
        EnsureLoggedIn();

        var options = new PrefillOptions();

        if (command.Parameters != null)
        {
            if (bool.TryParse(command.Parameters.GetValueOrDefault("all"), out var all))
                options.DownloadAllOwnedGames = all;
            if (bool.TryParse(command.Parameters.GetValueOrDefault("recent"), out var recent))
                options.PrefillRecentGames = recent;
            if (bool.TryParse(command.Parameters.GetValueOrDefault("recentlyPurchased"), out var purchased))
                options.PrefillRecentlyPurchased = purchased;
            if (int.TryParse(command.Parameters.GetValueOrDefault("top"), out var top))
                options.PrefillTopGames = top;
            if (bool.TryParse(command.Parameters.GetValueOrDefault("force"), out var force))
                options.Force = force;
        }

        return await _api!.PrefillAsync(options, _cts.Token);
    }

    private void HandleShutdown()
    {
        HandleLogout();
    }

    private void EnsureLoggedIn()
    {
        if (!_isLoggedIn || _api == null || !_api.IsInitialized)
            throw new InvalidOperationException("Not logged in. Please login first.");
    }

    private async Task WriteStatusAsync(string status, string message)
    {
        var statusResponse = new DaemonStatus
        {
            Type = "status-update",
            Status = status,
            Message = message,
            Timestamp = DateTime.UtcNow
        };

        var fileName = "daemon_status.json";
        var filePath = Path.Combine(_responsesDir, fileName);
        var json = JsonSerializer.Serialize(statusResponse, DaemonSerializationContext.Default.DaemonStatus);
        await File.WriteAllTextAsync(filePath, json, _cts.Token);
    }

    private async Task WriteResponseAsync(CommandResponse response)
    {
        var fileName = $"response_{response.Id}.json";
        var filePath = Path.Combine(_responsesDir, fileName);

        var json = JsonSerializer.Serialize(response, DaemonSerializationContext.Default.CommandResponse);
        await File.WriteAllTextAsync(filePath, json, _cts.Token);

        _progress.OnLog(LogLevel.Debug, $"Response written: {fileName}");
    }

    public void Dispose()
    {
        if (_isDisposed)
            return;

        Stop();
        _cts.Dispose();
        _api?.Dispose();
        _authProvider.Dispose();
        _commandLock.Dispose();
        _isDisposed = true;

        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Command request format for file-based interface
/// </summary>
public class CommandRequest
{
    /// <summary>
    /// Unique ID for this command (for correlating responses)
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Command type: login, get-owned-games, set-selected-apps, prefill, etc.
    /// </summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>
    /// Optional parameters for the command
    /// </summary>
    public Dictionary<string, string>? Parameters { get; set; }

    /// <summary>
    /// When the command was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Command response format
/// </summary>
public class CommandResponse
{
    /// <summary>
    /// ID matching the request
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Whether the command succeeded
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Optional success message
    /// </summary>
    public string? Message { get; set; }

    /// <summary>
    /// Error message if failed
    /// </summary>
    public string? Error { get; set; }

    /// <summary>
    /// Response data (varies by command)
    /// </summary>
    public object? Data { get; set; }

    /// <summary>
    /// If true, login is required before this command can be executed
    /// </summary>
    public bool? RequiresLogin { get; set; }

    /// <summary>
    /// When the command completed
    /// </summary>
    public DateTime CompletedAt { get; set; }
}
