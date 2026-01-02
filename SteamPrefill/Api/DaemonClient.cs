using System.Text.Json;

namespace SteamPrefill.Api;

/// <summary>
/// Client library for communicating with SteamPrefill daemon.
/// This can be used from a web API to securely control prefill containers.
///
/// Usage:
/// 1. Create DaemonClient pointing to the container's command/response directories
/// 2. Call LoginAsync() - this will trigger encrypted credential challenges
/// 3. Provide credentials securely using ProvideCredentialAsync()
/// 4. Use other commands after login succeeds
///
/// All credentials are encrypted using ECDH key exchange + AES-GCM
/// </summary>
public sealed class DaemonClient : IDisposable
{
    private readonly string _commandsDir;
    private readonly string _responsesDir;
    private readonly FileSystemWatcher? _responseWatcher;
    private readonly Dictionary<string, TaskCompletionSource<CommandResponse>> _pendingCommands = new();
    private readonly Dictionary<string, TaskCompletionSource<CredentialChallenge>> _pendingChallenges = new();
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    public DaemonClient(string commandsDir, string responsesDir)
    {
        _commandsDir = commandsDir;
        _responsesDir = responsesDir;

        Directory.CreateDirectory(_commandsDir);
        Directory.CreateDirectory(_responsesDir);

        // Watch for responses
        _responseWatcher = new FileSystemWatcher(_responsesDir, "*.json")
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };
        _responseWatcher.Created += OnResponseFileCreated;
    }

    private async void OnResponseFileCreated(object sender, FileSystemEventArgs e)
    {
        try
        {
            await Task.Delay(50); // Ensure file is written

            var json = await File.ReadAllTextAsync(e.FullPath);

            // Check if it's a credential challenge
            if (json.Contains("\"type\":\"credential-challenge\"", StringComparison.OrdinalIgnoreCase) ||
                json.Contains("\"type\": \"credential-challenge\"", StringComparison.OrdinalIgnoreCase))
            {
                var challenge = JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.CredentialChallenge);
                if (challenge != null)
                {
                    lock (_pendingChallenges)
                    {
                        if (_pendingChallenges.TryGetValue("pending", out var tcs))
                        {
                            tcs.TrySetResult(challenge);
                        }
                    }
                }
                return;
            }

            // Check if it's a command response
            if (json.Contains("\"id\"", StringComparison.OrdinalIgnoreCase))
            {
                var response = JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.CommandResponse);
                if (response != null)
                {
                    lock (_pendingCommands)
                    {
                        if (_pendingCommands.TryGetValue(response.Id, out var tcs))
                        {
                            tcs.TrySetResult(response);
                            _pendingCommands.Remove(response.Id);
                        }
                    }

                    // Clean up response file
                    try { File.Delete(e.FullPath); } catch { }
                }
            }
        }
        catch
        {
            // Ignore parse errors
        }
    }

    /// <summary>
    /// Get the current daemon status
    /// </summary>
    public async Task<DaemonStatus?> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var statusPath = Path.Combine(_responsesDir, "daemon_status.json");
        if (!File.Exists(statusPath))
            return null;

        var json = await File.ReadAllTextAsync(statusPath, cancellationToken);
        return JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.DaemonStatus);
    }

    /// <summary>
    /// Send a command to the daemon and wait for response
    /// </summary>
    public async Task<CommandResponse> SendCommandAsync(
        string type,
        Dictionary<string, string>? parameters = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var command = new CommandRequest
        {
            Id = Guid.NewGuid().ToString(),
            Type = type,
            Parameters = parameters,
            CreatedAt = DateTime.UtcNow
        };

        var tcs = new TaskCompletionSource<CommandResponse>();

        lock (_pendingCommands)
        {
            _pendingCommands[command.Id] = tcs;
        }

        try
        {
            // Write command file
            var json = JsonSerializer.Serialize(command, DaemonSerializationContext.Default.CommandRequest);
            var filePath = Path.Combine(_commandsDir, $"cmd_{command.Id}.json");
            await File.WriteAllTextAsync(filePath, json, cancellationToken);

            // Wait for response
            using var timeoutCts = new CancellationTokenSource(timeout ?? TimeSpan.FromMinutes(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var reg = linkedCts.Token.Register(() => tcs.TrySetCanceled());

            return await tcs.Task;
        }
        finally
        {
            lock (_pendingCommands)
            {
                _pendingCommands.Remove(command.Id);
            }
        }
    }

    /// <summary>
    /// Check for an existing credential challenge (already waiting for credentials)
    /// </summary>
    public async Task<CredentialChallenge?> GetPendingChallengeAsync(CancellationToken cancellationToken = default)
    {
        // Look for existing auth_challenge_*.json files
        var challengeFiles = Directory.GetFiles(_responsesDir, "auth_challenge_*.json");
        foreach (var file in challengeFiles)
        {
            try
            {
                var json = await File.ReadAllTextAsync(file, cancellationToken);
                var challenge = JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.CredentialChallenge);
                if (challenge != null && DateTime.UtcNow < challenge.ExpiresAt)
                {
                    return challenge;
                }
                // Delete expired challenges
                if (challenge != null && DateTime.UtcNow >= challenge.ExpiresAt)
                {
                    try { File.Delete(file); } catch { }
                }
            }
            catch { /* ignore parse errors */ }
        }
        return null;
    }

    /// <summary>
    /// Start login process. Returns a credential challenge that requires encrypted credentials.
    /// First checks for existing pending challenges before sending a new login command.
    /// </summary>
    public async Task<CredentialChallenge?> StartLoginAsync(
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        // First check if there's already a pending challenge
        var existingChallenge = await GetPendingChallengeAsync(cancellationToken);
        if (existingChallenge != null)
        {
            return existingChallenge;
        }

        var tcs = new TaskCompletionSource<CredentialChallenge>();

        lock (_pendingChallenges)
        {
            _pendingChallenges["pending"] = tcs;
        }

        try
        {
            // Send login command
            _ = SendCommandAsync("login", cancellationToken: cancellationToken);

            // Wait for credential challenge
            using var timeoutCts = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(30));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var reg = linkedCts.Token.Register(() => tcs.TrySetCanceled());

            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        finally
        {
            lock (_pendingChallenges)
            {
                _pendingChallenges.Remove("pending");
            }
        }
    }

    /// <summary>
    /// Provide an encrypted credential in response to a challenge.
    /// Use SecureCredentialExchange.EncryptCredential() to encrypt the credential.
    /// </summary>
    public async Task ProvideEncryptedCredentialAsync(
        EncryptedCredentialResponse encryptedCredential,
        CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(encryptedCredential, DaemonSerializationContext.Default.EncryptedCredentialResponse);
        var filePath = Path.Combine(_commandsDir, $"cred_{encryptedCredential.ChallengeId}.json");
        await File.WriteAllTextAsync(filePath, json, cancellationToken);
    }

    /// <summary>
    /// Convenience method to encrypt and provide a credential.
    /// This encrypts the credential using the challenge's public key.
    /// </summary>
    public async Task ProvideCredentialAsync(
        CredentialChallenge challenge,
        string credential,
        CancellationToken cancellationToken = default)
    {
        var encrypted = SecureCredentialExchange.EncryptCredential(
            challenge.ChallengeId,
            challenge.ServerPublicKey,
            credential);

        await ProvideEncryptedCredentialAsync(encrypted, cancellationToken);

        // Delete the challenge file after responding to prevent re-processing
        var challengeFile = Path.Combine(_responsesDir, $"auth_challenge_{challenge.ChallengeId}.json");
        try { File.Delete(challengeFile); } catch { /* ignore - server may have already deleted it */ }
    }

    /// <summary>
    /// Wait for the next credential challenge
    /// </summary>
    public async Task<CredentialChallenge?> WaitForChallengeAsync(
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        // First check for existing challenge
        var existingChallenge = await GetPendingChallengeAsync(cancellationToken);
        if (existingChallenge != null)
        {
            return existingChallenge;
        }

        var tcs = new TaskCompletionSource<CredentialChallenge>();

        lock (_pendingChallenges)
        {
            _pendingChallenges["pending"] = tcs;
        }

        try
        {
            using var timeoutCts = new CancellationTokenSource(timeout ?? TimeSpan.FromMinutes(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var reg = linkedCts.Token.Register(() => tcs.TrySetCanceled());

            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        finally
        {
            lock (_pendingChallenges)
            {
                _pendingChallenges.Remove("pending");
            }
        }
    }

    /// <summary>
    /// Get list of owned games (requires login)
    /// </summary>
    public async Task<List<OwnedGame>> GetOwnedGamesAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendCommandAsync("get-owned-games", cancellationToken: cancellationToken);

        if (!response.Success)
            throw new InvalidOperationException(response.Error ?? "Failed to get owned games");

        if (response.Data is JsonElement element)
        {
            return JsonSerializer.Deserialize(element.GetRawText(), DaemonSerializationContext.Default.ListOwnedGame)
                   ?? new List<OwnedGame>();
        }

        return new List<OwnedGame>();
    }

    /// <summary>
    /// Set selected apps for prefill (requires login)
    /// </summary>
    public async Task SetSelectedAppsAsync(List<uint> appIds, CancellationToken cancellationToken = default)
    {
        var response = await SendCommandAsync("set-selected-apps", new Dictionary<string, string>
        {
            ["appIds"] = JsonSerializer.Serialize(appIds, DaemonSerializationContext.Default.ListUInt32)
        }, cancellationToken: cancellationToken);

        if (!response.Success)
            throw new InvalidOperationException(response.Error ?? "Failed to set selected apps");
    }

    /// <summary>
    /// Start prefill (requires login)
    /// </summary>
    public async Task<PrefillResult> PrefillAsync(
        bool all = false,
        bool recent = false,
        bool force = false,
        CancellationToken cancellationToken = default)
    {
        var parameters = new Dictionary<string, string>();
        if (all) parameters["all"] = "true";
        if (recent) parameters["recent"] = "true";
        if (force) parameters["force"] = "true";

        var response = await SendCommandAsync("prefill", parameters,
            timeout: TimeSpan.FromHours(24), // Prefill can take a long time
            cancellationToken: cancellationToken);

        if (!response.Success)
            throw new InvalidOperationException(response.Error ?? "Prefill failed");

        if (response.Data is JsonElement element)
        {
            return JsonSerializer.Deserialize(element.GetRawText(), DaemonSerializationContext.Default.PrefillResult)
                   ?? new PrefillResult { Success = false, ErrorMessage = "Failed to parse result" };
        }

        return new PrefillResult { Success = true };
    }

    /// <summary>
    /// Shutdown the daemon
    /// </summary>
    public async Task ShutdownAsync(CancellationToken cancellationToken = default)
    {
        await SendCommandAsync("shutdown", timeout: TimeSpan.FromSeconds(30), cancellationToken: cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed) return;

        _responseWatcher?.Dispose();
        _lock.Dispose();

        foreach (var tcs in _pendingCommands.Values)
            tcs.TrySetCanceled();
        foreach (var tcs in _pendingChallenges.Values)
            tcs.TrySetCanceled();

        _disposed = true;
    }
}
