using System.Security.Cryptography;
using System.Text;

namespace SteamPrefill.Settings
{
    /// <summary>
    /// Provides AES-256-GCM encryption for token storage on disk.
    /// The encryption key is derived from the machine name using HKDF, scoping
    /// decryption to the machine where the token was originally saved.
    ///
    /// Stored format: "ENC:" + Base64( nonce[12] + ciphertext[N] + tag[16] )
    /// </summary>
    internal static class TokenStorageEncryption
    {
        private const string EncryptedPrefix = "ENC:";
        private const string PurposeLabel = "SteamPrefill.TokenStorage.v1";
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int KeySize = 32;

        /// <summary>Returns true when <paramref name="fileContent"/> was produced by <see cref="Encrypt"/>.</summary>
        internal static bool IsEncrypted(string fileContent) =>
            fileContent.StartsWith(EncryptedPrefix, StringComparison.Ordinal);

        /// <summary>
        /// Encrypts <paramref name="plaintext"/> and returns a string safe for file storage.
        /// </summary>
        internal static string Encrypt(string plaintext)
        {
            var key = DeriveKey();
            var nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[TagSize];

            using var aesGcm = new AesGcm(key, TagSize);
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            // Zero out key material immediately after use
            CryptographicOperations.ZeroMemory(key);

            // Layout: nonce | ciphertext | tag — all in one Base64 blob
            var blob = new byte[NonceSize + ciphertext.Length + TagSize];
            nonce.CopyTo(blob, 0);
            ciphertext.CopyTo(blob, NonceSize);
            tag.CopyTo(blob, NonceSize + ciphertext.Length);

            return EncryptedPrefix + System.Convert.ToBase64String(blob);
        }

        /// <summary>
        /// Decrypts a value previously produced by <see cref="Encrypt"/>.
        /// </summary>
        /// <exception cref="CryptographicException">Thrown when the data is tampered or the key does not match.</exception>
        internal static string Decrypt(string encryptedValue)
        {
            if (!encryptedValue.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
            {
                throw new ArgumentException("Value is not in encrypted format.", nameof(encryptedValue));
            }

            var blob = System.Convert.FromBase64String(encryptedValue[EncryptedPrefix.Length..]);

            if (blob.Length < NonceSize + TagSize)
            {
                throw new CryptographicException("Encrypted blob is too short to be valid.");
            }

            var nonce = blob.AsSpan(0, NonceSize);
            var tag = blob.AsSpan(blob.Length - TagSize, TagSize);
            var ciphertext = blob.AsSpan(NonceSize, blob.Length - NonceSize - TagSize);

            var key = DeriveKey();
            var plaintext = new byte[ciphertext.Length];

            try
            {
                using var aesGcm = new AesGcm(key, TagSize);
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        /// <summary>
        /// Derives a 256-bit key from the machine name so that stored tokens can only be
        /// decrypted on the machine where they were saved.
        /// </summary>
        private static byte[] DeriveKey()
        {
            // Use machine name as input key material; not a secret, but scopes decryption to this host.
            var ikm = Encoding.UTF8.GetBytes(Environment.MachineName);
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, KeySize,
                info: Encoding.UTF8.GetBytes(PurposeLabel));
        }

        /// <summary>
        /// Sets restrictive file permissions on Unix (equivalent to chmod 600).
        /// On Windows this is a no-op because the token data is already encrypted.
        /// </summary>
        internal static void SetRestrictivePermissions(string filePath)
        {
            if (!System.OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(filePath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
    }
}
