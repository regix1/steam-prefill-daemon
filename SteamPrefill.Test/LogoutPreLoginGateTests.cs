using System.Reflection;
using SteamPrefill.Api;
using SteamPrefill.Settings;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// Regression test for the erase-on-stop restart loop: SocketCommandInterface's PreLoginCommands
    /// allowlist gated every non-allowlisted command on _isLoggedIn, and "logout" was missing from it -
    /// so a logout sent to a container still sitting at a credential challenge (_isLoggedIn == false)
    /// was rejected by the gate before HandleLogoutAsync (itself unconditionally safe) ever ran.
    /// SocketCommandInterface has no public seam (it owns a live SocketServer, never bound here since
    /// StartAsync is never called), so this drives the private HandleCommandAsync gate via reflection.
    /// </summary>
    [Collection("SteamAccountFile")]
    public sealed class LogoutPreLoginGateTests : IDisposable
    {
        private readonly string _accountPath = AppConfig.AccountSettingsStorePath;
        private readonly bool _accountFileExisted;
        private readonly string? _originalAccountContent;

        public LogoutPreLoginGateTests()
        {
            _accountFileExisted = File.Exists(_accountPath);
            _originalAccountContent = _accountFileExisted ? File.ReadAllText(_accountPath) : null;
        }

        public void Dispose()
        {
            if (_accountFileExisted && _originalAccountContent != null)
            {
                File.WriteAllText(_accountPath, _originalAccountContent);
            }
            else
            {
                File.Delete(_accountPath);
            }
        }

        [Fact]
        public async Task Logout_WhileNotLoggedIn_IsNotRejectedByPreLoginGate()
        {
            using var socketInterface = new SocketCommandInterface(
                Path.Combine(Path.GetTempPath(), $"steam-prelogin-gate-{Guid.NewGuid():N}.sock"));

            var handleCommandAsync = typeof(SocketCommandInterface).GetMethod(
                "HandleCommandAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;

            var request = new CommandRequest { Id = "1", Type = "logout" };
            var response = await (Task<CommandResponse>)handleCommandAsync.Invoke(
                socketInterface, new object[] { request, CancellationToken.None })!;

            // Before the fix: Success=false, Error="Authentication required...", RequiresLogin=true -
            // the gate rejected the command before HandleLogoutAsync ever ran.
            Assert.True(response.Success);
            Assert.False(response.RequiresLogin);
        }
    }
}
