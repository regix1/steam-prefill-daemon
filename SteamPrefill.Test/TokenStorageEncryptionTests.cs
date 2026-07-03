using System.Security.Cryptography;
using SteamPrefill.Settings;
using Xunit;

namespace SteamPrefill.Test
{
    /// <summary>
    /// Covers the token-storage-at-rest key derivation (<see cref="TokenStorageEncryption"/>) and the
    /// guarded decrypt in <see cref="UserAccountStore.LoadFromFile"/>. Regression coverage for the bug
    /// where a key derived from the container hostname made the persistent volume's stored login
    /// undecryptable by any successor container, hard-crashing every login attempt.
    /// </summary>
    [Collection("SteamAccountFile")]
    public sealed class TokenStorageEncryptionTests : IDisposable
    {
        private readonly string _accountFilePath;
        private readonly string _keyFilePath;
        private readonly bool _accountFileExisted;
        private readonly string? _originalAccountFileContent;
        private readonly bool _keyFileExisted;
        private readonly string? _originalKeyFileContent;

        public TokenStorageEncryptionTests()
        {
            _accountFilePath = AppConfig.AccountSettingsStorePath;
            _keyFilePath = TokenStorageEncryption.KeyFilePath;

            _accountFileExisted = File.Exists(_accountFilePath);
            _originalAccountFileContent = _accountFileExisted ? File.ReadAllText(_accountFilePath) : null;
            _keyFileExisted = File.Exists(_keyFilePath);
            _originalKeyFileContent = _keyFileExisted ? File.ReadAllText(_keyFilePath) : null;

            DeleteIfExists(_accountFilePath);
            DeleteIfExists(_keyFilePath);
        }

        public void Dispose()
        {
            DeleteIfExists(_accountFilePath);
            DeleteIfExists(_keyFilePath);

            if (_accountFileExisted && _originalAccountFileContent != null)
            {
                File.WriteAllText(_accountFilePath, _originalAccountFileContent);
            }
            if (_keyFileExisted && _originalKeyFileContent != null)
            {
                File.WriteAllText(_keyFilePath, _originalKeyFileContent);
            }
        }

        private static void DeleteIfExists(string path)
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void EncryptDecrypt_StableKeyFile_RoundTrips()
        {
            var encrypted = TokenStorageEncryption.Encrypt("hello-world");

            var decrypted = TokenStorageEncryption.Decrypt(encrypted);

            Assert.Equal("hello-world", decrypted);
            Assert.True(File.Exists(_keyFilePath));
        }

        [Fact]
        public void LoadFromFile_KeyFileReplaced_ReturnsFreshStore_DoesNotThrow_DeletesStaleFile()
        {
            // Save an account under whatever key file gets created on first use.
            var original = UserAccountStore.LoadFromFile();
            original.SetCredentialsFromToken("someuser", "some-refresh-token");
            Assert.True(File.Exists(_accountFilePath));
            Assert.True(File.Exists(_keyFilePath));

            // Simulate a new container: the volume's account file survives, but the key file
            // it was encrypted under does not (this is what a stale/mismatched key file looks like).
            var newKey = new byte[32];
            RandomNumberGenerator.Fill(newKey);
            File.WriteAllText(_keyFilePath, Convert.ToBase64String(newKey));

            var reloaded = UserAccountStore.LoadFromFile();

            Assert.Null(reloaded.CurrentUsername);
            Assert.False(File.Exists(_accountFilePath));
        }

        [Fact]
        public void EncryptDecrypt_WrongLengthKeyFile_RegeneratesValidKey()
        {
            // Simulates a torn/partial write (valid Base64, wrong length) - before the length
            // validation hardening, this would be silently accepted as short/malformed HKDF input key
            // material forever instead of being detected and regenerated.
            var shortKey = new byte[16];
            RandomNumberGenerator.Fill(shortKey);
            File.WriteAllText(_keyFilePath, Convert.ToBase64String(shortKey));

            var encrypted = TokenStorageEncryption.Encrypt("hello-world");
            var decrypted = TokenStorageEncryption.Decrypt(encrypted);

            Assert.Equal("hello-world", decrypted);
            var regenerated = Convert.FromBase64String(File.ReadAllText(_keyFilePath).Trim());
            Assert.Equal(32, regenerated.Length);
        }

        [Fact]
        public void LoadFromFile_UndecryptableEncryptedBlob_ReturnsFreshStore_DoesNotThrow_DeletesStaleFile()
        {
            // Legacy-poisoned store: "ENC:"-prefixed but not decryptable under any key this
            // process holds (e.g. produced by a since-deleted key file). Before the guarded
            // decrypt fix, this makes Decrypt throw CryptographicException and LoadFromFile
            // crashes instead of falling back to a fresh interactive login.
            var garbage = new byte[12 + 32 + 16];
            RandomNumberGenerator.Fill(garbage);
            File.WriteAllText(_accountFilePath, "ENC:" + Convert.ToBase64String(garbage));

            var result = UserAccountStore.LoadFromFile();

            Assert.Null(result.CurrentUsername);
            Assert.False(File.Exists(_accountFilePath));
        }

        /// <summary>
        /// SocketCommandInterface has no test seam (it owns a live SocketServer/SteamPrefillApi and can't
        /// be constructed headlessly), so this covers the underlying guarantee HandleLogoutAsync relies
        /// on: deleting the account file makes a subsequent LoadFromFile() return a fresh, credential-less
        /// store - i.e. "logout" really forgets the account rather than just tearing down the live API
        /// instance.
        /// </summary>
        [Fact]
        public void DeletingAccountFile_ThenLoadFromFile_ReturnsFreshStore_WithNoStoredCredentials()
        {
            var original = UserAccountStore.LoadFromFile();
            original.SetCredentialsFromToken("someuser", "some-refresh-token");
            Assert.True(File.Exists(_accountFilePath));

            // This is exactly what HandleLogoutAsync does on logout: best-effort delete the persisted store.
            File.Delete(_accountFilePath);

            var reloaded = UserAccountStore.LoadFromFile();

            Assert.Null(reloaded.CurrentUsername);
            Assert.False(File.Exists(_accountFilePath));
        }
    }
}
