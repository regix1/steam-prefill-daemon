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
    /// Registers how the sign-in takes a Steam Guard code while Steam waits for the phone approval. Once the device
    /// confirmation is acknowledged, a provider that can ask for a code asks for one and hands it to
    /// <paramref name="sendCode"/>, asking again while that throws a SteamKit2 <c>AuthenticationException</c> (a code Steam
    /// refused). Disposing the registration ends the ask.
    /// </summary>
    IDisposable OnPhoneApprovalCode(Func<string, Task> sendCode);

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

    public IDisposable OnPhoneApprovalCode(Func<string, Task> sendCode)
        => NoPhoneApprovalCode.Instance; // Static provider has nobody to ask for a code

    public Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
        => Task.FromResult(_password);

    public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
        => Task.FromResult<string?>(_password);
}

/// <summary>
/// The registration a provider that never asks for a code during the phone approval hands back: nothing to end.
/// </summary>
public sealed class NoPhoneApprovalCode : IDisposable
{
    public static readonly NoPhoneApprovalCode Instance = new();

    private NoPhoneApprovalCode()
    {
    }

    public void Dispose()
    {
    }
}
