using System.Reflection;
using SteamPrefill.Api;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// HandleProvideCredential previously
    /// unconditionally returned Success = true "Credential received" even when the daemon had no
    /// matching pending challenge, so a misrouted credential from a stale/replaced login session was
    /// silently dropped while the manager believed it was accepted. A provide-credential with no
    /// pending challenge must now return Success = false so the manager can detect the desync.
    ///
    /// SocketCommandInterface owns a live SocketServer (never StartAsync'd here), so this drives the
    /// private HandleCommandAsync via reflection - the same seam as LogoutPreLoginGateTests. This path
    /// touches no on-disk store (the credential is rejected before any decryption), so it needs no
    /// SteamAccountFile collection.
    /// </summary>
    public sealed class ProvideCredentialNoPendingChallengeTests
    {
        [Fact]
        public async Task ProvideCredential_WithNoPendingChallenge_ReturnsFailure()
        {
            using var socketInterface = new SocketCommandInterface(
                Path.Combine(Path.GetTempPath(), $"steam-provide-credential-{Guid.NewGuid():N}.sock"));

            var handleCommandAsync = typeof(SocketCommandInterface).GetMethod(
                "HandleCommandAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

            // Well-formed parameters so the null/empty guard passes, but no login is in flight - the
            // auth provider has no pending challenge to match, so the credential is dropped.
            var request = new CommandRequest
            {
                Id = "1",
                Type = "provide-credential",
                Parameters = new Dictionary<string, string>
                {
                    ["challengeId"] = "no-such-challenge",
                    ["clientPublicKey"] = "AA==",
                    ["encryptedCredential"] = "AA==",
                    ["nonce"] = "AA==",
                    ["tag"] = "AA=="
                }
            };

            var response = await (Task<CommandResponse>)handleCommandAsync.Invoke(
                socketInterface, new object[] { request, CancellationToken.None })!;

            // Before the fix: Success = true, Message = "Credential received" - masking the drop.
            Assert.False(response.Success);
            Assert.Equal("No matching login challenge is pending for this credential", response.Error);
        }
    }
}
