using SteamPrefill.Api;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// Regression coverage for RC1 (session 20260703-221336-2070027597): SecureSteamAuthenticator
    /// unconditionally returned true from AcceptDeviceConfirmationAsync (including its catch path), so
    /// SteamKit2 3.4.0 polled for Steam Mobile App approval and never called the code getters - the
    /// 2FA / Steam Guard code modal never appeared for mobile-authenticator accounts.
    /// AcceptDeviceConfirmationAsync must now return false so SteamKit falls back to code entry, and the
    /// code getters must route through ISteamAuthProvider and re-request on retry.
    ///
    /// SecureSteamAuthenticator takes ISteamAuthProvider via constructor injection, so this uses a
    /// hand-rolled fake (project convention: no mocking framework) with no reflection.
    /// </summary>
    public sealed class SecureSteamAuthenticatorTests
    {
        [Fact]
        public async Task AcceptDeviceConfirmationAsync_ReturnsFalse_ToPreferCodeEntry()
        {
            var provider = new RecordingAuthProvider();
            var authenticator = new SecureSteamAuthenticator(provider);

            var accepted = await authenticator.AcceptDeviceConfirmationAsync();

            // Before the fix this returned true (and true again from its catch block), forcing SteamKit
            // to poll for mobile approval. False makes SteamKit fall back to the code-entry challenge.
            // The fix removed the try/catch entirely, so there is no longer a separate exception path
            // that can still return true.
            Assert.False(accepted);
            // Must NOT route through the device-confirmation channel that preempted the code getters.
            Assert.Equal(0, provider.DeviceConfirmationCallCount);
        }

        [Fact]
        public async Task GetDeviceCodeAsync_RoutesThroughProvider_AndReRequestsOnRetry()
        {
            var provider = new RecordingAuthProvider { TwoFactorCode = "123456" };
            var authenticator = new SecureSteamAuthenticator(provider);

            var first = await authenticator.GetDeviceCodeAsync(previousCodeWasIncorrect: false);
            var second = await authenticator.GetDeviceCodeAsync(previousCodeWasIncorrect: true);

            Assert.Equal("123456", first);
            Assert.Equal("123456", second);
            // A second call (previousCodeWasIncorrect == true) re-requests a fresh code from the
            // provider rather than replaying a cached one or hanging.
            Assert.Equal(2, provider.TwoFactorCallCount);
        }

        [Fact]
        public async Task GetDeviceCodeAsync_EmptyCode_AbortsWithoutHanging()
        {
            var provider = new RecordingAuthProvider { TwoFactorCode = string.Empty };
            var authenticator = new SecureSteamAuthenticator(provider);

            // An empty/null code from the provider is SteamKit's documented "give up" signal - the call
            // returns promptly instead of hanging, and SteamKit turns it into a clean abort.
            var code = await authenticator.GetDeviceCodeAsync(previousCodeWasIncorrect: false);

            Assert.Equal(string.Empty, code);
        }

        [Fact]
        public async Task GetEmailCodeAsync_RoutesThroughProvider_WithEmail()
        {
            var provider = new RecordingAuthProvider { SteamGuardCode = "ABCDE" };
            var authenticator = new SecureSteamAuthenticator(provider);

            var code = await authenticator.GetEmailCodeAsync("user@example.com", previousCodeWasIncorrect: false);

            Assert.Equal("ABCDE", code);
            Assert.Equal("user@example.com", provider.LastSteamGuardEmail);
        }

        /// <summary>
        /// Hand-rolled ISteamAuthProvider fake modeled on StaticAuthProvider, with call counters so
        /// tests can prove routing and re-request behavior without a mocking framework.
        /// </summary>
        private sealed class RecordingAuthProvider : ISteamAuthProvider
        {
            public string TwoFactorCode { get; init; } = "000000";
            public string SteamGuardCode { get; init; } = "AAAAA";
            public int TwoFactorCallCount { get; private set; }
            public int SteamGuardCallCount { get; private set; }
            public int DeviceConfirmationCallCount { get; private set; }
            public string? LastSteamGuardEmail { get; private set; }

            public Task<string> GetUsernameAsync(CancellationToken cancellationToken = default)
                => Task.FromResult("username");

            public Task<string> GetPasswordAsync(CancellationToken cancellationToken = default)
                => Task.FromResult("password");

            public Task<string> GetSteamGuardCodeAsync(string email, CancellationToken cancellationToken = default)
            {
                SteamGuardCallCount++;
                LastSteamGuardEmail = email;
                return Task.FromResult(SteamGuardCode);
            }

            public Task<string> GetTwoFactorCodeAsync(CancellationToken cancellationToken = default)
            {
                TwoFactorCallCount++;
                return Task.FromResult(TwoFactorCode);
            }

            public Task GetDeviceConfirmationAsync(CancellationToken cancellationToken = default)
            {
                DeviceConfirmationCallCount++;
                return Task.CompletedTask;
            }

            public Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
                => Task.FromResult("password");

            public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
                => Task.FromResult<string?>(null);
        }
    }
}
