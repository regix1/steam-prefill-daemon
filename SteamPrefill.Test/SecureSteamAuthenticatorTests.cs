using SteamPrefill.Api;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// SecureSteamAuthenticator takes ISteamAuthProvider via constructor injection, so this uses a
    /// hand-rolled fake (project convention: no mocking framework) with no reflection.
    /// </summary>
    public sealed class SecureSteamAuthenticatorTests
    {
        [Fact]
        public async Task AcceptDeviceConfirmationAsync_AcceptsAndRoutesThroughProvider()
        {
            var provider = new RecordingAuthProvider();
            var authenticator = new SecureSteamAuthenticator(provider);

            var accepted = await authenticator.AcceptDeviceConfirmationAsync();

            // Accepting device confirmation lets SteamKit poll for Steam Mobile App approval, and the
            // client is notified via the device-confirmation credential channel so it can show the
            // "check your phone" step.
            Assert.True(accepted);
            Assert.Equal(1, provider.DeviceConfirmationCallCount);
        }

        [Fact]
        public async Task AcceptDeviceConfirmationAsync_ProviderThrows_StillReturnsTrue()
        {
            var provider = new RecordingAuthProvider { ThrowOnDeviceConfirmation = true };
            var authenticator = new SecureSteamAuthenticator(provider);

            // A failure notifying the client (e.g. the socket briefly disconnected) must not stop
            // SteamKit from proceeding to poll for the real Steam-side approval.
            var accepted = await authenticator.AcceptDeviceConfirmationAsync();

            Assert.True(accepted);
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
            public bool ThrowOnDeviceConfirmation { get; init; }
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
                if (ThrowOnDeviceConfirmation)
                {
                    throw new InvalidOperationException("Simulated failure notifying the client");
                }
                return Task.CompletedTask;
            }

            public Task<string> GetNewPasswordAsync(string message, CancellationToken cancellationToken = default)
                => Task.FromResult("password");

            public Task<string?> GetCachedPasswordAsync(CancellationToken cancellationToken = default)
                => Task.FromResult<string?>(null);
        }
    }
}
