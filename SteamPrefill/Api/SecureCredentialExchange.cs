#nullable enable

using System.Security.Cryptography;
using System.Text;
using Convert = System.Convert;

namespace SteamPrefill.Api;

/// <summary>
/// Secure credential exchange using ECDH key exchange and AES-GCM encryption.
/// This prevents plain text credentials from ever being transmitted in clear text.
///
/// Protocol:
/// 1. Server generates ephemeral ECDH keypair
/// 2. Server sends public key + challenge via socket
/// 3. Client generates ephemeral ECDH keypair
/// 4. Client derives shared secret, encrypts credentials with AES-GCM
/// 5. Client sends encrypted credentials + client public key via socket
/// 6. Server derives same shared secret, decrypts credentials
/// 7. Server uses credentials immediately, then securely clears memory
/// </summary>
public sealed class SecureCredentialExchange : IDisposable
{
    private readonly string _challengeId;
    private byte[]? _serverPrivateKey;
    private byte[]? _serverPublicKey;
    private bool _disposed;

    // Current active challenge
    private static SecureCredentialExchange? _currentChallenge;
    private static readonly object _lock = new();

    public string ChallengeId => _challengeId;
    public bool IsExpired => DateTime.UtcNow > _expiresAt;
    private readonly DateTime _expiresAt;

    private SecureCredentialExchange()
    {
        _challengeId = Guid.NewGuid().ToString("N");
        _expiresAt = DateTime.UtcNow.AddMinutes(5); // Challenge expires in 5 minutes
        GenerateKeyPair();
    }

    private void GenerateKeyPair()
    {
        // Generate ECDH keypair for Diffie-Hellman key exchange
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdh.ExportParameters(true);

        // Store private key securely
        _serverPrivateKey = parameters.D;

        // Export public key
        _serverPublicKey = new byte[65]; // Uncompressed point format
        _serverPublicKey[0] = 0x04; // Uncompressed point indicator
        Array.Copy(parameters.Q.X!, 0, _serverPublicKey, 1, 32);
        Array.Copy(parameters.Q.Y!, 0, _serverPublicKey, 33, 32);
    }

    /// <summary>
    /// Creates a new credential challenge.
    /// The challenge is sent via socket to the client.
    /// </summary>
    public static CredentialChallenge CreateChallenge(string credentialType, string? email = null)
    {
        lock (_lock)
        {
            // Dispose previous challenge
            _currentChallenge?.Dispose();

            var exchange = new SecureCredentialExchange();
            _currentChallenge = exchange;

            // Return challenge object (caller sends it via socket)
            return new CredentialChallenge
            {
                ChallengeId = exchange._challengeId,
                CredentialType = credentialType,
                Email = email,
                ServerPublicKey = Convert.ToBase64String(exchange._serverPublicKey!),
                ExpiresAt = exchange._expiresAt,
                CreatedAt = DateTime.UtcNow
            };
        }
    }

    /// <summary>
    /// Decrypts credentials from an encrypted credential response.
    /// Returns null if decryption fails or challenge is invalid/expired.
    /// </summary>
    public static string? DecryptCredential(EncryptedCredentialResponse response)
    {
        lock (_lock)
        {
            if (_currentChallenge == null)
                return null;

            if (_currentChallenge._challengeId != response.ChallengeId)
                return null;

            if (_currentChallenge.IsExpired)
            {
                _currentChallenge.Dispose();
                _currentChallenge = null;
                return null;
            }

            try
            {
                var credential = _currentChallenge.DecryptInternal(response);

                // Dispose challenge after use - one-time use only
                _currentChallenge.Dispose();
                _currentChallenge = null;

                return credential;
            }
            catch
            {
                return null;
            }
        }
    }

    private string? DecryptInternal(EncryptedCredentialResponse response)
    {
        if (_serverPrivateKey == null)
            return null;

        try
        {
            // Parse client public key
            var clientPublicKeyBytes = Convert.FromBase64String(response.ClientPublicKey);

            // Recreate our ECDH instance
            using var serverEcdh = ECDiffieHellman.Create();
            var serverParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = _serverPrivateKey,
                Q = new ECPoint
                {
                    X = _serverPublicKey!.AsSpan(1, 32).ToArray(),
                    Y = _serverPublicKey!.AsSpan(33, 32).ToArray()
                }
            };
            serverEcdh.ImportParameters(serverParams);

            // Import client public key
            using var clientEcdh = ECDiffieHellman.Create();
            var clientParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = clientPublicKeyBytes.AsSpan(1, 32).ToArray(),
                    Y = clientPublicKeyBytes.AsSpan(33, 32).ToArray()
                }
            };
            clientEcdh.ImportParameters(clientParams);

            // Derive shared secret
            var sharedSecret = serverEcdh.DeriveKeyMaterial(clientEcdh.PublicKey);

            // Derive AES key from shared secret using HKDF
            var aesKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                sharedSecret,
                32, // 256-bit key
                Encoding.UTF8.GetBytes(_challengeId),
                Encoding.UTF8.GetBytes("SteamPrefill-Credential-Encryption"));

            // Decrypt with AES-GCM
            var nonce = Convert.FromBase64String(response.Nonce);
            var ciphertext = Convert.FromBase64String(response.EncryptedCredential);
            var tag = Convert.FromBase64String(response.Tag);

            var plaintext = new byte[ciphertext.Length];
            using var aesGcm = new AesGcm(aesKey, 16);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);

            var credential = Encoding.UTF8.GetString(plaintext);

            // Securely clear sensitive data
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(plaintext);

            return credential;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (_serverPrivateKey != null)
        {
            CryptographicOperations.ZeroMemory(_serverPrivateKey);
            _serverPrivateKey = null;
        }

        _serverPublicKey = null;
        _disposed = true;
    }
}

/// <summary>
/// Challenge sent to client requesting encrypted credentials
/// </summary>
public class CredentialChallenge
{
    public string Type => "credential-challenge";
    public string ChallengeId { get; init; } = string.Empty;
    public string CredentialType { get; init; } = string.Empty; // "username", "password", "2fa", "steamguard"
    public string? Email { get; init; }
    public string ServerPublicKey { get; init; } = string.Empty;
    public DateTime CreatedAt { get; init; }
    public DateTime ExpiresAt { get; init; }
}

/// <summary>
/// Encrypted credential response from client
/// </summary>
public class EncryptedCredentialResponse
{
    public string ChallengeId { get; init; } = string.Empty;
    public string ClientPublicKey { get; init; } = string.Empty;
    public string EncryptedCredential { get; init; } = string.Empty;
    public string Nonce { get; init; } = string.Empty;
    public string Tag { get; init; } = string.Empty;
}
