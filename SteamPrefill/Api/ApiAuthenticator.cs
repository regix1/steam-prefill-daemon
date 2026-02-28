#nullable enable

using SteamKit2;
using SteamKit2.Authentication;

namespace SteamPrefill.Api;

/// <summary>
/// Custom SteamKit2 authenticator that uses ISteamAuthProvider for credential input.
/// This replaces the default UserConsoleAuthenticator for non-CLI scenarios.
/// </summary>
public class ApiAuthenticator : IAuthenticator
{
    private readonly ISteamAuthProvider _authProvider;
    private readonly IPrefillProgress _progress;

    public ApiAuthenticator(ISteamAuthProvider authProvider, IPrefillProgress? progress = null)
    {
        _authProvider = authProvider ?? throw new ArgumentNullException(nameof(authProvider));
        _progress = progress ?? NullProgress.Instance;
    }

    /// <summary>
    /// Called when Steam Guard code (sent via email) is required
    /// </summary>
    public async Task<string> GetDeviceCodeAsync(bool previousCodeWasIncorrect)
    {
        if (previousCodeWasIncorrect)
        {
            _progress.OnLog(LogLevel.Warning, "Previous Steam Guard code was incorrect. Please try again.");
        }

        _progress.OnLog(LogLevel.Info, "Steam Guard code required (check your Steam mobile app)");

        try
        {
            return await _authProvider.GetTwoFactorCodeAsync(default);
        }
        catch (Exception ex)
        {
            _progress.OnError("Failed to get Steam Guard code", ex);
            throw;
        }
    }

    /// <summary>
    /// Called when 2FA code from mobile authenticator is required
    /// </summary>
    public async Task<string> GetEmailCodeAsync(string email, bool previousCodeWasIncorrect)
    {
        if (previousCodeWasIncorrect)
        {
            _progress.OnLog(LogLevel.Warning, "Previous 2FA code was incorrect. Please try again.");
        }

        _progress.OnLog(LogLevel.Info, $"Email verification code required (sent to {MaskEmail(email)})");

        try
        {
            return await _authProvider.GetSteamGuardCodeAsync(email);
        }
        catch (Exception ex)
        {
            _progress.OnError("Failed to get email verification code", ex);
            throw;
        }
    }

    /// <summary>
    /// Called to confirm device approval (mobile app confirmation)
    /// </summary>
    public Task<bool> AcceptDeviceConfirmationAsync()
    {
        _progress.OnLog(LogLevel.Info, "Please confirm this login on your Steam mobile app...");

        // For now, we'll wait for the user to confirm on mobile
        // The polling will handle the actual confirmation
        return Task.FromResult(true);
    }

    private static string MaskEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
            return "***";

        var atIndex = email.IndexOf('@');
        if (atIndex <= 1)
            return "***" + email[atIndex..];

        return email[0] + "***" + email[(atIndex - 1)..];
    }
}
