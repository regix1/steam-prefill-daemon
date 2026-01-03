#nullable enable

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SteamPrefill.Api;

/// <summary>
/// Secure authentication provider for daemon mode.
/// Uses encrypted credential exchange to prevent plain text credentials from being written to disk.
///
/// Security features:
/// - ECDH key exchange for each credential request
/// - AES-GCM encryption for credentials in transit
/// - Secure memory handling (pinned, zeroed after use)
/// - Challenge-response with expiration
/// - One-time use challenges (replay attack prevention)
/// </summary>
public sealed class SecureDaemonAuthProvider : ISteamAuthProvider, IDisposable
{
    private readonly string _commandsDir;
    private readonly string _responsesDir;
    private readonly IPrefillProgress _progress;
    private readonly FileSystemWatcher _watcher;
    private readonly SemaphoreSlim _credentialLock = new(1, 1);
    private TaskCompletionSource<string>? _pendingCredential;
    private string? _currentChallengeId;
    private bool _disposed;

    // Store credentials securely in pinned memory
    private GCHandle _credentialHandle;
    private char[]? _pinnedCredential;

    public SecureDaemonAuthProvider(string commandsDir, string responsesDir, IPrefillProgress progress)
    {
        _commandsDir = commandsDir;
        _responsesDir = responsesDir;
        _progress = progress;

        Directory.CreateDirectory(_commandsDir);
        Directory.CreateDirectory(_responsesDir);

        // Watch for encrypted credential responses
        _watcher = new FileSystemWatcher(_commandsDir, "*.json")
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
            EnableRaisingEvents = true
        };
        _watcher.Created += OnCredentialFileCreated;
    }

    private async void OnCredentialFileCreated(object sender, FileSystemEventArgs e)
    {
        if (_pendingCredential == null || _currentChallengeId == null)
            return;

        try
        {
            await Task.Delay(50); // Ensure file is fully written

            var json = await File.ReadAllTextAsync(e.FullPath);

            // Check if this is an encrypted credential response
            if (!json.Contains("encryptedCredential", StringComparison.OrdinalIgnoreCase))
                return;

            var response = JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.EncryptedCredentialResponse);
            if (response == null || response.ChallengeId != _currentChallengeId)
                return;

            // Decrypt the credential
            var credential = SecureCredentialExchange.DecryptCredential(response);

            // Delete the command file immediately
            try { File.Delete(e.FullPath); } catch { /* ignore */ }

            if (credential != null)
            {
                _progress.OnLog(LogLevel.Debug, "Credential received and decrypted successfully");
                _pendingCredential?.TrySetResult(credential);
            }
            else
            {
                _progress.OnError("Failed to decrypt credential - invalid or expired challenge");
            }
        }
        catch (Exception ex)
        {
            _progress.OnError($"Error processing credential file: {ex.Message}");
        }
    }

    private async Task<string> RequestSecureCredentialAsync(string credentialType, string? email, CancellationToken cancellationToken)
    {
        await _credentialLock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<string>();

            // Create secure challenge
            var challenge = SecureCredentialExchange.CreateChallenge(_responsesDir, credentialType, email);
            _currentChallengeId = challenge.ChallengeId;

            _progress.OnLog(LogLevel.Info, $"Waiting for encrypted {credentialType} credential...");

            // Wait for credential with timeout
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var reg = linkedCts.Token.Register(() => _pendingCredential.TrySetCanceled());

            try
            {
                var credential = await _pendingCredential.Task;

                // Store in secure pinned memory
                StoreSecurely(credential);

                return credential;
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                throw new TimeoutException($"Timeout waiting for {credentialType} credential");
            }
        }
        finally
        {
            _currentChallengeId = null;
            _credentialLock.Release();
        }
    }

    private void StoreSecurely(string credential)
    {
        // Clear previous pinned credential
        ClearPinnedCredential();

        // Pin new credential in memory to prevent GC from moving it
        _pinnedCredential = credential.ToCharArray();
        _credentialHandle = GCHandle.Alloc(_pinnedCredential, GCHandleType.Pinned);
    }

    private void ClearPinnedCredential()
    {
        if (_pinnedCredential != null)
        {
            // Zero out the memory
            Array.Clear(_pinnedCredential, 0, _pinnedCredential.Length);

            if (_credentialHandle.IsAllocated)
            {
                _credentialHandle.Free();
            }

            _pinnedCredential = null;
        }
    }

    public Task<string> GetUsernameAsync(CancellationToken cancellationToken = default)
        => RequestSecureCredentialAsync("username", null, cancellationToken);

    public Task<string> GetPasswordAsync(CancellationToken cancellationToken = default)
        => RequestSecureCredentialAsync("password", null, cancellationToken);

    public Task<string> GetSteamGuardCodeAsync(string email, CancellationToken cancellationToken = default)
        => RequestSecureCredentialAsync("steamguard", email, cancellationToken);

    public Task<string> GetTwoFactorCodeAsync(CancellationToken cancellationToken = default)
        => RequestSecureCredentialAsync("2fa", null, cancellationToken);

    public async Task GetDeviceConfirmationAsync(CancellationToken cancellationToken = default)
    {
        // Send a device-confirmation challenge to notify the client to check their Steam app
        await RequestSecureCredentialAsync("device-confirmation", null, cancellationToken);
    }

    public Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
    {
        _progress.OnLog(LogLevel.Warning, message);
        return RequestSecureCredentialAsync("password", null, cancellationToken);
    }

    public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(null); // Daemon always requires secure credential exchange

    /// <summary>
    /// Cancels any pending credential request and clears challenge files.
    /// Call this when the user wants to abort a login attempt.
    /// </summary>
    public void CancelPendingRequest()
    {
        _progress.OnLog(LogLevel.Info, "Cancelling pending credential request...");

        // Cancel the pending credential wait
        _pendingCredential?.TrySetCanceled();
        _pendingCredential = null;
        _currentChallengeId = null;

        // Clear any pending challenge files
        try
        {
            var challengeFiles = Directory.GetFiles(_responsesDir, "auth_challenge_*.json");
            foreach (var file in challengeFiles)
            {
                try { File.Delete(file); } catch { /* ignore */ }
            }
            _progress.OnLog(LogLevel.Debug, $"Cleared {challengeFiles.Length} challenge file(s)");
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Error clearing challenge files: {ex.Message}");
        }

        // Clear any stored credentials
        ClearPinnedCredential();

        _progress.OnLog(LogLevel.Info, "Pending credential request cancelled");
    }

    public void Dispose()
    {
        if (_disposed) return;

        ClearPinnedCredential();
        _watcher.Dispose();
        _credentialLock.Dispose();
        _pendingCredential?.TrySetCanceled();
        _disposed = true;
    }
}
