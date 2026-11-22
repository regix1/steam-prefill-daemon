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
    private PhoneApprovalCodeAsk? _phoneApprovalCode;
    private bool _disposed;

    // Store credentials securely in pinned memory
    private GCHandle _credentialHandle;
    private char[]? _pinnedCredential;
    private readonly object _pinnedLock = new();

    public SocketAuthProvider(SocketServer socketServer, IPrefillProgress? progress = null)
    {
        _socketServer = socketServer;
        _progress = progress ?? NullProgress.Instance;
    }

    /// <summary>
    /// Called by the SocketCommandInterface when a provide-credential command is received.
    ///
    /// Returns whether the credential matched a live pending challenge. It returns <c>false</c> when no challenge is pending or the
    /// challenge id does not match, so the caller can reply <c>Success = false</c> instead of masking a
    /// dropped credential as a success. A misrouted credential from a stale/replaced login session
    /// would otherwise be silently discarded here while the client believed it was accepted.
    /// </summary>
    public bool ReceiveCredential(EncryptedCredentialResponse response)
    {
        // Read once: a cancel-login on another thread can clear the field between the check and the use.
        var pending = _pendingCredential;
        if (pending == null || _currentChallengeId == null)
        {
            _progress.OnLog(LogLevel.Warning, "Received credential but no challenge is pending");
            return false;
        }

        if (response.ChallengeId != _currentChallengeId)
        {
            _progress.OnLog(LogLevel.Warning, $"Received credential for wrong challenge. Expected: {_currentChallengeId}, Got: {response.ChallengeId}");
            return false;
        }

        _progress.OnLog(LogLevel.Debug, "Credential received via socket");
        pending.TrySetResult(response);
        return true;
    }

    private async Task<string> RequestSecureCredentialAsync(string credentialType, string? email, CancellationToken cancellationToken)
    {
        await _credentialLock.WaitAsync(cancellationToken);
        try
        {
            // Kept in a local too: a cancel-login clears the field while the challenge is still being sent.
            var pending = new TaskCompletionSource<EncryptedCredentialResponse>();
            _pendingCredential = pending;

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
            using var reg = linkedCts.Token.Register(() => pending.TrySetCanceled());

            try
            {
                var encryptedResponse = await pending.Task;

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
                throw new AuthenticationException($"Timeout waiting for {credentialType} credential");
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
        lock (_pinnedLock)
        {
            // Clear previous pinned credential
            ClearPinnedCredential();

            // Pin new credential in memory to prevent GC from moving it
            _pinnedCredential = credential.ToCharArray();
            _credentialHandle = GCHandle.Alloc(_pinnedCredential, GCHandleType.Pinned);
        }
    }

    // A logout clears the pinned credential on its own thread while a submitted one may be stored, so the
    // clear and the store each run whole under one lock.
    private void ClearPinnedCredential()
    {
        lock (_pinnedLock)
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
        // Steam also takes a code while it waits for the phone, so the client is asked for one beside the wait.
        _phoneApprovalCode?.Start();
    }

    public IDisposable OnPhoneApprovalCode(Func<string, Task> sendCode)
    {
        var registration = new PhoneApprovalCodeAsk(this, sendCode);
        _phoneApprovalCode = registration;
        return registration;
    }

    /// <summary>
    /// Asks the client for a code while Steam waits for the phone approval and hands it to the sign-in, asking again for
    /// each code Steam refuses. Disposing it ends the ask and waits for it, so the credential lock it holds is free for
    /// the next request.
    /// </summary>
    private sealed class PhoneApprovalCodeAsk(SocketAuthProvider auth, Func<string, Task> sendCode) : IDisposable
    {
        private readonly object _lock = new();
        private readonly CancellationTokenSource _ended = new();
        private Task? _asking;
        private bool _disposed;

        public void Start()
        {
            lock (_lock)
            {
                if (_disposed || _asking != null) return;
                _asking = AskAsync(_ended.Token);
            }
        }

        private async Task AskAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (true)
                {
                    var code = await auth.GetTwoFactorCodeAsync(cancellationToken);
                    try
                    {
                        await sendCode(code);
                        return;
                    }
                    catch (SteamKit2.Authentication.AuthenticationException)
                    {
                        auth._progress.OnLog(LogLevel.Info, "Steam did not accept the code typed during the phone approval; asking again");
                    }
                }
            }
            // The sign-in ended (this registration's dispose, or a cancel-login clearing the pending request).
            catch (OperationCanceledException)
            {
            }
            // The five-minute wait for the code ran out, or the code could not be decrypted (RequestSecureCredentialAsync),
            // or Steam failed the send's job: the phone approval goes on without a code.
            catch (Exception ex) when (ex is AuthenticationException or InvalidOperationException or SteamKit2.AsyncJobFailedException)
            {
                auth._progress.OnLog(LogLevel.Warning, $"Stopped asking for a code during the phone approval: {ex.Message}");
            }
        }

        public void Dispose()
        {
            Task? asking;
            lock (_lock)
            {
                if (_disposed) return;
                _disposed = true;
                _ended.Cancel();
                asking = _asking;
            }
            asking?.GetAwaiter().GetResult();
            _ended.Dispose();
            if (ReferenceEquals(auth._phoneApprovalCode, this)) auth._phoneApprovalCode = null;
        }
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
        _progress.OnLog(LogLevel.Info, "Canceling pending credential request...");

        _pendingCredential?.TrySetCanceled();
        _pendingCredential = null;
        _currentChallengeId = null;

        ClearPinnedCredential();

        _progress.OnLog(LogLevel.Info, "Pending credential request canceled");
    }

    /// <summary>
    /// Gets the current challenge ID (for validation).
    /// </summary>
    public string? CurrentChallengeId => _currentChallengeId;

    public void Dispose()
    {
        if (_disposed) return;

        ClearPinnedCredential();
        // Ends a code ask still running, which holds the credential lock disposed next.
        _phoneApprovalCode?.Dispose();
        _credentialLock.Dispose();
        _pendingCredential?.TrySetCanceled();
        _disposed = true;
    }
}
