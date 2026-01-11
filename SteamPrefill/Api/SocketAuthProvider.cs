#nullable enable

using System.Runtime.InteropServices;
using System.Text.Json;

namespace SteamPrefill.Api;

/// <summary>
/// Authentication provider that uses Unix Domain Socket for credential exchange.
/// Instead of writing challenge files, it sends challenges directly through the socket
/// and waits for encrypted credential responses.
///
/// Flow:
/// 1. Steam requests credentials → this provider sends a credential-challenge event via socket
/// 2. Client receives challenge, encrypts credentials, sends provide-credential command
/// 3. This provider decrypts and returns the credential
///
/// This eliminates FileSystemWatcher reliability issues.
/// </summary>
public sealed class SocketAuthProvider : ISteamAuthProvider, IDisposable
{
    private readonly SocketServer _socketServer;
    private readonly IPrefillProgress _progress;
    private readonly SemaphoreSlim _credentialLock = new(1, 1);
    private TaskCompletionSource<EncryptedCredentialResponse>? _pendingCredential;
    private string? _currentChallengeId;
    private bool _disposed;

    // Store credentials securely in pinned memory
    private GCHandle _credentialHandle;
    private char[]? _pinnedCredential;

    public SocketAuthProvider(SocketServer socketServer, IPrefillProgress? progress = null)
    {
        _socketServer = socketServer;
        _progress = progress ?? NullProgress.Instance;
    }

    /// <summary>
    /// Called by the SocketCommandInterface when a provide-credential command is received.
    /// </summary>
    public void ReceiveCredential(EncryptedCredentialResponse response)
    {
        if (_pendingCredential == null || _currentChallengeId == null)
        {
            _progress.OnLog(LogLevel.Warning, "Received credential but no challenge is pending");
            return;
        }

        if (response.ChallengeId != _currentChallengeId)
        {
            _progress.OnLog(LogLevel.Warning, $"Received credential for wrong challenge. Expected: {_currentChallengeId}, Got: {response.ChallengeId}");
            return;
        }

        _progress.OnLog(LogLevel.Debug, "Credential received via socket");
        _pendingCredential.TrySetResult(response);
    }

    private async Task<string> RequestSecureCredentialAsync(string credentialType, string? email, CancellationToken cancellationToken)
    {
        await _credentialLock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<EncryptedCredentialResponse>();

            // Create secure challenge using existing encryption infrastructure
            var challenge = SecureCredentialExchange.CreateChallenge(credentialType, email);
            _currentChallengeId = challenge.ChallengeId;

            _progress.OnLog(LogLevel.Info, $"Sending credential challenge via socket: {credentialType} (id: {challenge.ChallengeId})");

            // Send challenge event to all connected clients via socket
            var challengeEvent = new CredentialChallengeEvent(challenge);
            await _socketServer.BroadcastCredentialChallengeAsync(challengeEvent, cancellationToken);

            // Wait for credential with timeout
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            using var reg = linkedCts.Token.Register(() => _pendingCredential.TrySetCanceled());

            try
            {
                var encryptedResponse = await _pendingCredential.Task;

                // Decrypt the credential
                var credential = SecureCredentialExchange.DecryptCredential(encryptedResponse);
                if (credential == null)
                {
                    throw new InvalidOperationException("Failed to decrypt credential - invalid or expired challenge");
                }

                _progress.OnLog(LogLevel.Debug, "Credential decrypted successfully");

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
            _pendingCredential = null;
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
        => Task.FromResult<string?>(null); // Always requires secure credential exchange

    /// <summary>
    /// Cancels any pending credential request.
    /// </summary>
    public void CancelPendingRequest()
    {
        _progress.OnLog(LogLevel.Info, "Cancelling pending credential request...");

        _pendingCredential?.TrySetCanceled();
        _pendingCredential = null;
        _currentChallengeId = null;

        ClearPinnedCredential();

        _progress.OnLog(LogLevel.Info, "Pending credential request cancelled");
    }

    /// <summary>
    /// Gets the current challenge ID (for validation).
    /// </summary>
    public string? CurrentChallengeId => _currentChallengeId;

    public void Dispose()
    {
        if (_disposed) return;

        ClearPinnedCredential();
        _credentialLock.Dispose();
        _pendingCredential?.TrySetCanceled();
        _disposed = true;
    }
}
