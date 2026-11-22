using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SteamPrefill.Api;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// While Steam waits for the phone approval, the sign-in window also offers a Steam Guard code. The code the user types
    /// then arrives as a <c>2fa</c> credential through the socket, and the daemon has to hand it to the sign-in that is
    /// waiting instead of dropping it. The test plays the browser: it answers each challenge the daemon sends.
    /// </summary>
    // The challenge being answered is the process-wide current one, so no other test may create a challenge meanwhile.
    [Collection("SteamAccountFile")]
    public sealed class PhoneApprovalCodeTests
    {
        private static readonly Regex ChallengeSent = new(@"^Sending credential challenge via socket: (\S+) \(id: (\S+)\)$");

        [Fact]
        public async Task ACodeTypedDuringThePhoneWaitIsHandedToTheSignIn()
        {
            var progress = new CallbackProgress();
            await using var server = new SocketServer(Path.Combine(Path.GetTempPath(), $"steam-phone-code-{Guid.NewGuid():N}.sock"));
            using var auth = new SocketAuthProvider(server, progress);
            var challenges = new Queue<(string Type, string Id)>();
            progress.LogReceived += (_, message) =>
            {
                var sent = ChallengeSent.Match(message);
                if (!sent.Success) return;
                lock (challenges) challenges.Enqueue((sent.Groups[1].Value, sent.Groups[2].Value));
            };

            var handOff = typeof(SocketAuthProvider).GetMethod("OnPhoneApprovalCode", [typeof(Func<string, Task>)]);
            Assert.True(handOff is not null,
                "the daemon has no way to hand a code typed during the phone wait to the sign-in, so a 2fa credential sent then is dropped");

            var codes = new List<string>();
            using var registration = (IDisposable)handOff!.Invoke(auth, [(Func<string, Task>)(code =>
            {
                lock (codes) codes.Add(code);
                return Task.CompletedTask;
            })])!;
            var phoneWait = auth.GetDeviceConfirmationAsync();

            var deadline = DateTime.UtcNow.AddSeconds(10);
            var codeSent = false;
            while (!codeSent && DateTime.UtcNow < deadline)
            {
                (string Type, string Id)? next = null;
                lock (challenges) if (challenges.Count > 0) next = challenges.Dequeue();
                if (next is null)
                {
                    await Task.Delay(10);
                    continue;
                }

                var (type, id) = next.Value;
                var answer = type == "2fa" ? "ABCDE" : "confirm";
                Assert.True(auth.ReceiveCredential(EncryptForCurrentChallenge(id, answer)),
                    $"the daemon dropped the browser's answer to its {type} challenge");
                codeSent = type == "2fa";
            }

            Assert.True(codeSent, "the daemon never asked for a code during the phone wait, so the browser has nowhere to send one");
            deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                lock (codes) if (codes.Count > 0) break;
                await Task.Delay(10);
            }

            lock (codes) Assert.Equal(new[] { "ABCDE" }, codes);
            auth.CancelPendingRequest();
            await Record.ExceptionAsync(() => phoneWait.WaitAsync(TimeSpan.FromSeconds(10)));
        }

        private const string ApprovedThenReleased = "the phone approves, then the sign-in drops its code hand-off";
        private const string ReleasedThenApproved = "the sign-in drops its code hand-off, then the phone approves";

        /// <summary>
        /// Once the phone wait is over and the sign-in has dropped its code hand-off, a later code request (Steam asking
        /// for a code on the next sign-in) must reach the browser and take the code it sends, not wait behind the ended
        /// phone wait. Both orders of the approval and the release run.
        /// </summary>
        [Theory]
        [InlineData(ApprovedThenReleased)]
        [InlineData(ReleasedThenApproved)]
        public async Task ACodeAskedForAfterTheHandOffIsReleasedIsNotBlocked(string order)
        {
            var progress = new CallbackProgress();
            await using var server = new SocketServer(Path.Combine(Path.GetTempPath(), $"steam-phone-code-{Guid.NewGuid():N}.sock"));
            using var auth = new SocketAuthProvider(server, progress);
            var challenges = new Queue<(string Type, string Id)>();
            progress.LogReceived += (_, message) =>
            {
                var sent = ChallengeSent.Match(message);
                if (!sent.Success) return;
                lock (challenges) challenges.Enqueue((sent.Groups[1].Value, sent.Groups[2].Value));
            };

            var handOff = typeof(SocketAuthProvider).GetMethod("OnPhoneApprovalCode", [typeof(Func<string, Task>)]);
            Assert.True(handOff is not null,
                "the daemon has no way to hand a code typed during the phone wait to the sign-in, so a 2fa credential sent then is dropped");
            var registration = (IDisposable)handOff!.Invoke(auth, [(Func<string, Task>)(_ => Task.CompletedTask)])!;
            var phoneWait = auth.GetDeviceConfirmationAsync();
            var phoneChallenge = await NextChallengeAsync(challenges, "device-confirmation");
            Assert.True(phoneChallenge is not null, "the daemon never told the browser to wait for the phone");

            if (order == ReleasedThenApproved) registration.Dispose();
            Assert.True(auth.ReceiveCredential(EncryptForCurrentChallenge(phoneChallenge!, "confirm")),
                "the daemon dropped the browser's answer to its device-confirmation challenge");
            // How the phone wait itself ends is not what this test checks, only that it ended.
            await Record.ExceptionAsync(() => phoneWait.WaitAsync(TimeSpan.FromSeconds(10)));
            if (order == ApprovedThenReleased) registration.Dispose();

            // Whatever the phone wait announced before it ended is old; only a challenge sent for the new request counts.
            lock (challenges) challenges.Clear();
            var laterCode = auth.GetTwoFactorCodeAsync();
            var codeChallenge = await NextChallengeAsync(challenges, "2fa");
            Assert.True(codeChallenge is not null,
                $"after {order}, a later request for a code never asked the browser for one: it is held behind the ended phone wait");
            Assert.True(auth.ReceiveCredential(EncryptForCurrentChallenge(codeChallenge!, "FGHIJ")),
                $"after {order}, the daemon dropped the browser's answer to the later code request");
            string? code = null;
            var received = await Record.ExceptionAsync(async () => code = await laterCode.WaitAsync(TimeSpan.FromSeconds(10)));
            Assert.True(received is null && code == "FGHIJ",
                $"after {order}, the later code request did not take the code the browser sent ({code}): {received?.GetType().Name}");
        }

        /// <summary>The id of the next challenge of <paramref name="type"/> the daemon sends within ten seconds, passing over
        /// challenges of other types, or null when none is sent.</summary>
        private static async Task<string?> NextChallengeAsync(Queue<(string Type, string Id)> challenges, string type)
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline)
            {
                (string Type, string Id)? next = null;
                lock (challenges) if (challenges.Count > 0) next = challenges.Dequeue();
                if (next is null)
                {
                    await Task.Delay(10);
                    continue;
                }

                if (next.Value.Type == type) return next.Value.Id;
            }

            return null;
        }

        /// <summary>Encrypts a credential the way the manager does for the daemon's current challenge: ECDH P-256 with the
        /// challenge's server key, HKDF-SHA256 salted with the challenge id, then AES-GCM.</summary>
        private static EncryptedCredentialResponse EncryptForCurrentChallenge(string challengeId, string credential)
        {
            var current = typeof(SecureCredentialExchange)
                .GetField("_currentChallenge", BindingFlags.NonPublic | BindingFlags.Static)!.GetValue(null)!;
            Assert.Equal(challengeId, ((SecureCredentialExchange)current).ChallengeId);
            var serverKey = (byte[])typeof(SecureCredentialExchange)
                .GetField("_serverPublicKey", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(current)!;

            using var server = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = serverKey[1..33], Y = serverKey[33..65] }
            });
            using var client = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var clientPoint = client.ExportParameters(false).Q;
            var sharedSecret = client.DeriveKeyMaterial(server.PublicKey);
            var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32,
                Encoding.UTF8.GetBytes(challengeId), Encoding.UTF8.GetBytes("SteamPrefill-Credential-Encryption"));

            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintext = Encoding.UTF8.GetBytes(credential);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(key, 16))
            {
                aes.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            var clientKey = new byte[65];
            clientKey[0] = 0x04;
            clientPoint.X!.CopyTo(clientKey, 1);
            clientPoint.Y!.CopyTo(clientKey, 33);
            return new EncryptedCredentialResponse
            {
                ChallengeId = challengeId,
                ClientPublicKey = Convert.ToBase64String(clientKey),
                EncryptedCredential = Convert.ToBase64String(ciphertext),
                Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag)
            };
        }
    }
}
