using SteamKit2.Authentication;

namespace SteamPrefill.Api;

/// <summary>
/// Custom SteamKit2 authenticator that routes Steam Guard and 2FA prompts
/// through our secure ISteamAuthProvider instead of console prompts.
/// </summary>
public sealed class SecureSteamAuthenticator : IAuthenticator
{
    private readonly ISteamAuthProvider _authProvider;

    public SecureSteamAuthenticator(ISteamAuthProvider authProvider)
    {
        _authProvider = authProvider ?? throw new ArgumentNullException(nameof(authProvider));
    }

    /// <summary>
    /// Called when Steam Mobile Authenticator code is required (TOTP)
    /// </summary>
    public async Task<string> GetDeviceCodeAsync(bool previousCodeWasIncorrect)
    {
        // Steam Mobile Authenticator TOTP code - route through our secure provider
        return await _authProvider.GetTwoFactorCodeAsync();
    }

    /// <summary>
    /// Called when Steam Guard code is required (email-based)
    /// </summary>
    public async Task<string> GetEmailCodeAsync(string email, bool previousCodeWasIncorrect)
    {
        // Email-based Steam Guard code
        return await _authProvider.GetSteamGuardCodeAsync(email);
    }

    /// <summary>
    /// Called when Steam offers mobile-app "device confirmation" (approve the sign-in inside the
    /// Steam Mobile App) as the top-priority confirmation type.
    ///
    /// Session 20260703-221336-2070027597 (RC1): returns <c>false</c> so SteamKit2 falls back to the
    /// next allowed confirmation type (TOTP authenticator code or email Steam Guard) and calls
    /// <see cref="GetDeviceCodeAsync"/>/<see cref="GetEmailCodeAsync"/>, which emit the code-entry
    /// challenge the client renders as the 2FA / Steam Guard modal. The previous unconditional
    /// <c>true</c> (including its catch path) made SteamKit poll for mobile approval and never call the
    /// code getters, so the modal never appeared for mobile-authenticator accounts. Accounts that offer
    /// ONLY mobile-app confirmation with no code fallback cause SteamKit to throw
    /// <see cref="InvalidOperationException"/>; that edge is surfaced as a clear login failure by the
    /// login task in SocketCommandInterface, not swallowed here.
    /// </summary>
    public Task<bool> AcceptDeviceConfirmationAsync() => Task.FromResult(false);
}
