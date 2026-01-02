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
    /// Called when device confirmation is required (Steam Mobile App approval)
    /// This is when Steam shows "Use the Steam Mobile App to confirm your sign in"
    /// </summary>
    public async Task<bool> AcceptDeviceConfirmationAsync()
    {
        // Notify the user that they need to approve on their mobile app
        // We use a special credential type to signal this to the client
        try
        {
            // Request a "device-confirmation" credential which signals the client
            // to display the mobile app approval message
            await _authProvider.GetDeviceConfirmationAsync();
            return true;
        }
        catch
        {
            // If anything fails, still return true to let SteamKit continue polling
            return true;
        }
    }
}
