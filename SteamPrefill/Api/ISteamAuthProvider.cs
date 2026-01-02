#nullable enable

namespace SteamPrefill.Api;

/// <summary>
/// Interface for providing Steam authentication credentials.
/// Implement this to provide credentials from different sources (CLI, web, file, etc.)
/// </summary>
public interface ISteamAuthProvider
{
    /// <summary>
    /// Gets the Steam username. Can be async for interactive scenarios.
    /// </summary>
    Task<string> GetUsernameAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the Steam password. Can be async for interactive scenarios.
    /// </summary>
    Task<string> GetPasswordAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the Steam Guard code (email verification).
    /// Called when Steam requires email-based 2FA.
    /// </summary>
    Task<string> GetSteamGuardCodeAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the 2FA code from Steam Mobile Authenticator.
    /// Called when Steam requires mobile app 2FA.
    /// </summary>
    Task<string> GetTwoFactorCodeAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Called when Steam requires device confirmation via the Steam Mobile App.
    /// This notifies the client to check their Steam app and approve the login request.
    /// Returns when the client acknowledges receiving the notification.
    /// </summary>
    Task GetDeviceConfirmationAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Called when the auth token has expired and new credentials are needed.
    /// </summary>
    Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default);

    /// <summary>
    /// Called when the previous access token is stored and password is not required.
    /// Returns null to skip password entry, or a password if one is available.
    /// </summary>
    Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Simple implementation that uses pre-configured credentials.
/// Useful for programmatic/API access where credentials are provided upfront.
/// </summary>
public class StaticAuthProvider : ISteamAuthProvider
{
    private readonly string _username;
    private readonly string _password;
    private readonly Func<Task<string>>? _twoFactorCallback;
    private readonly Func<string, Task<string>>? _steamGuardCallback;

    public StaticAuthProvider(
        string username,
        string password,
        Func<Task<string>>? twoFactorCallback = null,
        Func<string, Task<string>>? steamGuardCallback = null)
    {
        _username = username ?? throw new ArgumentNullException(nameof(username));
        _password = password ?? throw new ArgumentNullException(nameof(password));
        _twoFactorCallback = twoFactorCallback;
        _steamGuardCallback = steamGuardCallback;
    }

    public Task<string> GetUsernameAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_username);

    public Task<string> GetPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult(_password);

    public Task<string> GetSteamGuardCodeAsync(string email, CancellationToken cancellationToken = default)
    {
        if (_steamGuardCallback == null)
            throw new InvalidOperationException("Steam Guard code required but no callback provided");
        return _steamGuardCallback(email);
    }

    public Task<string> GetTwoFactorCodeAsync(CancellationToken cancellationToken = default)
    {
        if (_twoFactorCallback == null)
            throw new InvalidOperationException("Two-factor code required but no callback provided");
        return _twoFactorCallback();
    }

    public Task GetDeviceConfirmationAsync(CancellationToken cancellationToken = default)
        => Task.CompletedTask; // Static provider can't prompt for device confirmation

    public Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
        => Task.FromResult(_password);

    public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(_password);
}

/// <summary>
/// Event-based auth provider that raises events when credentials are needed.
/// Useful for web/UI scenarios where you need to prompt users asynchronously.
/// </summary>
public class EventAuthProvider : ISteamAuthProvider
{
    private TaskCompletionSource<string>? _pendingCredential;
    private readonly SemaphoreSlim _lock = new(1, 1);

    /// <summary>
    /// Raised when username is needed
    /// </summary>
    public event EventHandler? UsernameRequired;

    /// <summary>
    /// Raised when password is needed
    /// </summary>
    public event EventHandler? PasswordRequired;

    /// <summary>
    /// Raised when Steam Guard (email) code is needed. Email address is in EventArgs.
    /// </summary>
    public event EventHandler<string>? SteamGuardRequired;

    /// <summary>
    /// Raised when 2FA code from mobile authenticator is needed
    /// </summary>
    public event EventHandler? TwoFactorRequired;

    /// <summary>
    /// Raised when device confirmation via Steam Mobile App is required
    /// </summary>
    public event EventHandler? DeviceConfirmationRequired;

    /// <summary>
    /// Call this to provide the requested credential
    /// </summary>
    public void ProvideCredential(string credential)
    {
        _pendingCredential?.TrySetResult(credential);
    }

    /// <summary>
    /// Call this to cancel the pending credential request
    /// </summary>
    public void CancelCredentialRequest()
    {
        _pendingCredential?.TrySetCanceled();
    }

    public async Task<string> GetUsernameAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<string>();
            UsernameRequired?.Invoke(this, EventArgs.Empty);
            using var reg = cancellationToken.Register(() => _pendingCredential.TrySetCanceled());
            return await _pendingCredential.Task;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<string> GetPasswordAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<string>();
            PasswordRequired?.Invoke(this, EventArgs.Empty);
            using var reg = cancellationToken.Register(() => _pendingCredential.TrySetCanceled());
            return await _pendingCredential.Task;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<string> GetSteamGuardCodeAsync(string email, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<string>();
            SteamGuardRequired?.Invoke(this, email);
            using var reg = cancellationToken.Register(() => _pendingCredential.TrySetCanceled());
            return await _pendingCredential.Task;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<string> GetTwoFactorCodeAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<string>();
            TwoFactorRequired?.Invoke(this, EventArgs.Empty);
            using var reg = cancellationToken.Register(() => _pendingCredential.TrySetCanceled());
            return await _pendingCredential.Task;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task GetDeviceConfirmationAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            _pendingCredential = new TaskCompletionSource<string>();
            DeviceConfirmationRequired?.Invoke(this, EventArgs.Empty);
            using var reg = cancellationToken.Register(() => _pendingCredential.TrySetCanceled());
            await _pendingCredential.Task; // Wait for acknowledgment
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
        => await GetPasswordAsync(cancellationToken);

    public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(null); // Event provider always prompts
}
