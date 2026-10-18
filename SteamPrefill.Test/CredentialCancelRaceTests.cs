using SteamPrefill.Api;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// A cancel-login clears the pending credential request on another thread. Each test lands that cancel at one point
    /// inside the socket auth through its own log line, which it writes at that point, so the timing is fixed.
    /// </summary>
    public sealed class CredentialCancelRaceTests
    {
        [Fact]
        public async Task ACancelBetweenTheCheckAndTheUseOfACredentialEndsTheRequest()
        {
            var progress = new CallbackProgress();
            await using var server = new SocketServer(Path.Combine(Path.GetTempPath(), $"steam-auth-race-{Guid.NewGuid():N}.sock"));
            using var auth = new SocketAuthProvider(server, progress);
            var request = auth.GetUsernameAsync();
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (auth.CurrentChallengeId is null && DateTime.UtcNow < deadline)
            {
                await Task.Delay(10);
            }
            var challengeId = auth.CurrentChallengeId;
            Assert.NotNull(challengeId);

            // The socket auth logs at Debug after its checks and before it hands the credential over.
            progress.LogReceived += (level, _) =>
            {
                if (level == LogLevel.Debug) auth.CancelPendingRequest();
            };

            Assert.Null(Record.Exception(() => auth.ReceiveCredential(new EncryptedCredentialResponse { ChallengeId = challengeId! })));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => request);
        }

        [Fact]
        public async Task ACancelWhileTheChallengeIsSentEndsTheRequest()
        {
            var progress = new CallbackProgress();
            await using var server = new SocketServer(Path.Combine(Path.GetTempPath(), $"steam-auth-race-{Guid.NewGuid():N}.sock"));
            using var auth = new SocketAuthProvider(server, progress);
            // The socket auth's first Info line is written just before it sends the challenge.
            var canceled = false;
            progress.LogReceived += (level, _) =>
            {
                if (level != LogLevel.Info || canceled) return;
                canceled = true;
                auth.CancelPendingRequest();
            };

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => auth.GetUsernameAsync());
        }

        [Fact]
        public async Task AClearOfThePinnedCredentialWaitsWhileItIsInUse()
        {
            var progress = new CallbackProgress();
            await using var server = new SocketServer(Path.Combine(Path.GetTempPath(), $"steam-auth-race-{Guid.NewGuid():N}.sock"));
            using var auth = new SocketAuthProvider(server, progress);
            using var cleared = new ManualResetEventSlim();
            progress.LogReceived += (_, message) =>
            {
                if (message == "Pending credential request cancelled") cleared.Set();
            };
            // The test holds the lock a credential store holds while it swaps the pinned credential.
            var pinned = typeof(SocketAuthProvider)
                .GetField("_pinnedLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
                .GetValue(auth)!;

            Task cancel;
            Monitor.Enter(pinned);
            try
            {
                cancel = Task.Run(auth.CancelPendingRequest);
                Assert.False(cleared.Wait(TimeSpan.FromMilliseconds(300)));
            }
            finally
            {
                Monitor.Exit(pinned);
            }

            await cancel.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(cleared.IsSet);
        }
    }
}
