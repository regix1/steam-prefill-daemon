#nullable enable

using System.Text.Json;
using System.Threading;

namespace SteamPrefill.Api;

/// <summary>
/// Command interface that uses Unix Domain Socket for IPC.
/// This is the recommended interface for production use due to its reliability
/// compared to file-based communication.
///
/// Features:
/// - Real-time bidirectional communication
/// - Reliable message delivery (no FileSystemWatcher issues)
/// - Lower latency than file-based approach
/// - Works in both Docker host and bridge network modes
/// </summary>
public sealed class SocketCommandInterface : IDisposable
{
    private readonly SocketServer _socketServer;
    private readonly SocketAuthProvider _authProvider;
    private readonly SocketProgress _progress;
    private readonly CancellationTokenSource _cts = new();
    private readonly OwnedOperationCoordinator _prefillOperation;
    private readonly PrefillProtocol _protocol = PrefillProtocol.FromEnvironment(30, AppConfig.MaxConcurrencyOverride);
    private readonly RequestBudget _budget;
    private readonly TimeProvider _clock;
    private readonly ItemClaims _claims = new();
    private readonly Dictionary<string, PrefillRun> _runs = new(StringComparer.Ordinal);
    private CancellationTokenSource? _loginCts;
    private SteamPrefillApi? _api;
    private Task? _loginTask;
    private bool _isLoggedIn => _api?.IsInitialized == true;
    private readonly object _lifecycle = new();
    private Task _statusPublication = Task.CompletedTask;
    private bool _isLoggingIn;
    private bool _disposed;

    // All generation changes and credential commits share the lifecycle gate.
    private long _loginGeneration;

    // Why the daemon last signed out, kept while it stays signed out. Read and written under _lifecycle.
    private string? _signOutCode;


    // Auto-login challenge storage
    private readonly Dictionary<string, AutoLoginChallengeData> _pendingAutoLoginChallenges = new();

    // Commands allowed before login
    private static readonly HashSet<string> PreLoginCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "login",
        "logout",
        "status",
        "get-operation",
        "shutdown",
        "cancel-prefill",
        "cancel-login",
        "provide-credential",
        "get-auto-login-challenge",
        "provide-auto-login"
    };

    public SocketCommandInterface(string socketPath)
        : this(socketPath, TimeProvider.System)
    {
    }

    internal SocketCommandInterface(string socketPath, TimeProvider clock)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _prefillOperation = new OwnedOperationCoordinator(_protocol.MaxConcurrentRuns);
        _budget = new RequestBudget(_protocol.MaxConcurrentRequests);
        _progress = new SocketProgress(enableDebugLogs: AppConfig.DebugLogs);
        _socketServer = new SocketServer(socketPath, _progress);
        _authProvider = new SocketAuthProvider(_socketServer, _progress);
        _socketServer.OnCommand = HandleCommandAsync;
        _socketServer.CommandLaneSelector = request => ClassifyCommand(request.Type);
    }

    public SocketCommandInterface(int tcpPort)
        : this(tcpPort, TimeProvider.System)
    {
    }

    internal SocketCommandInterface(int tcpPort, TimeProvider clock)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _prefillOperation = new OwnedOperationCoordinator(_protocol.MaxConcurrentRuns);
        _budget = new RequestBudget(_protocol.MaxConcurrentRequests);
        _progress = new SocketProgress(enableDebugLogs: AppConfig.DebugLogs);
        _socketServer = new SocketServer(tcpPort, _progress);
        _authProvider = new SocketAuthProvider(_socketServer, _progress);
        _socketServer.OnCommand = HandleCommandAsync;
        _socketServer.CommandLaneSelector = request => ClassifyCommand(request.Type);
    }

    /// <summary>
    /// Start the socket server and begin accepting connections.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _progress.OnLog(LogLevel.Info, "Starting socket command interface...");

        await _socketServer.StartAsync(cancellationToken);

        // Send initial status
        await BroadcastStatusAsync("awaiting-login", "Login required before other commands can be executed");

        _progress.OnLog(LogLevel.Info, "Socket command interface started - awaiting login");
    }

    /// <summary>
    /// Stop the socket server and disconnect all clients.
    /// </summary>
    public async Task StopAsync()
    {
        _cts.Cancel();
        await EndSessionAsync(false);
        await _socketServer.StopAsync();
        _progress.OnLog(LogLevel.Info, "Socket command interface stopped");
    }

    private async Task<CommandResponse> HandleCommandAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        _progress.OnLog(LogLevel.Info, $"Processing command: {request.Type} (ID: {request.Id})");

        // Security check: Reject non-login commands if not authenticated
        if (!_isLoggedIn && !PreLoginCommands.Contains(request.Type))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "Authentication required. Please login first.",
                RequiresLogin = true,
                CompletedAt = DateTime.UtcNow
            };
        }

        try
        {
            return request.Type.ToLowerInvariant() switch
            {
                "login" => await HandleLoginAsync(request, cancellationToken),
                "logout" => await HandleLogoutAsync(request, cancellationToken),
                "cancel-login" => await HandleCancelLoginAsync(request),
                "cancel-prefill" => await HandleCancelPrefillAsync(request, cancellationToken),
                "provide-credential" => HandleProvideCredential(request),
                "get-auto-login-challenge" => HandleGetAutoLoginChallenge(request),
                "provide-auto-login" => await HandleProvideAutoLoginAsync(request, cancellationToken),
                "status" => HandleStatus(request),
                "get-operation" => HandleOperation(request),
                "get-owned-games" => await HandleGetOwnedGamesAsync(request, cancellationToken),
                "get-selected-apps" => HandleGetSelectedApps(request),
                "set-selected-apps" => HandleSetSelectedApps(request),
                "prefill" => await HandlePrefillAsync(request, cancellationToken),
                "clear-cache" => HandleClearCache(request),
                "get-cache-info" => HandleGetCacheInfo(request),
                "get-selected-apps-status" => await HandleGetSelectedAppsStatusAsync(request, cancellationToken),
                "check-cache-status" => await HandleCheckCacheStatusAsync(request, cancellationToken),
                "shutdown" => await HandleShutdownAsync(request, cancellationToken),
                _ => new CommandResponse
                {
                    Id = request.Id,
                    Success = false,
                    Error = "The prefill daemon could not complete the request. Try again.",
                    CompletedAt = DateTime.UtcNow
                }
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            FileLogger.LogException((ex as SteamConnectionException)?.GetContext(request.Type, request.Id) ?? $"Command={request.Type} operationId={request.Id}", ex);
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = ex is SteamConnectionException { Failure: not null } ? ex.Message : "The prefill daemon could not complete the request. Try again.",
                ErrorCode = (ex as SteamConnectionException)?.ErrorCode,
                RequiresLogin = (ex as SteamConnectionException)?.RequiresLogin == true,
                CompletedAt = DateTime.UtcNow
            };
        }
    }

    private Task<CommandResponse> HandleLoginAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        lock (_lifecycle)
        {
            if (!_isLoggedIn && !_isLoggingIn) StartLogin(null, null);
            return Task.FromResult(new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Message = _isLoggedIn ? "Already logged in" : "Login started - awaiting credentials",
                CompletedAt = DateTime.UtcNow
            });
        }
    }

    private void StartLogin(string? username, string? token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _cts.Token.ThrowIfCancellationRequested();
        if (_prefillOperation.IsRunning) throw new InvalidOperationException("Active operations must drain before login.");
        var previous = _api;
        var previousLogin = _loginTask;
        var generation = ++_loginGeneration;
        var cancellation = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
        var loginToken = cancellation.Token;
        _loginCts = cancellation;
        _isLoggingIn = true;
        // The code described the sign-in that ended; while this one runs, no reader may act on it.
        _signOutCode = null;
        SteamPrefillApi? api = null;
        void Commit(Action save)
        {
            lock (_lifecycle)
            {
                if (_disposed || generation != _loginGeneration || !ReferenceEquals(api, _api) ||
                    cancellation.IsCancellationRequested || (!_isLoggingIn && api?.IsInitialized != true))
                    throw new OperationCanceledException(loginToken);
                save();
            }
        }
        api = new SteamPrefillApi(_authProvider, _progress, Commit, _clock);
        _api = api;
        api.AuthenticationLost += result => HandleAuthenticationLost(api, generation, result);
        if (username != null && token != null)
        {
            var account = UserAccountStore.LoadFromFile(Commit);
            account.SetCredentialsFromToken(username, token);
        }
        _loginTask = Task.Run(async () =>
        {
            try
            {
                if (previousLogin != null) await previousLogin;
                if (previous != null) DisposeOrphanedApi(previous);
                await api.InitializeAsync(cancellation.Token);
                lock (_lifecycle)
                {
                    if (generation != _loginGeneration || !ReferenceEquals(_api, api)) return;
                    cancellation.Token.ThrowIfCancellationRequested();
                    if (!api.IsInitialized) throw new SteamConnectionException(SteamFailure.AuthLost);
                    _isLoggingIn = false;
                    // A later shutdown push must not repeat the reason for an earlier sign-out.
                    _signOutCode = null;
                    _statusPublication = PublishStatusAsync(_statusPublication, "logged-in", "Authenticated and ready for commands");
                }
            }
            catch (Exception ex)
            {
                if (ex is not OperationCanceledException) FileLogger.LogException("Steam login failed", ex);
                lock (_lifecycle)
                {
                    if (generation == _loginGeneration && ReferenceEquals(_api, api))
                    {
                        _api = null;
                        if (_isLoggingIn)
                        {
                            _signOutCode = SignOutCodeAfterUnfinishedSignIn(ex);
                            _statusPublication = PublishStatusAsync(_statusPublication, "awaiting-login",
                                "Steam sign-in did not complete. Sign in again.", _signOutCode);
                        }
                        _isLoggingIn = false;
                    }
                }
            }
            finally
            {
                bool orphan;
                lock (_lifecycle)
                {
                    orphan = !ReferenceEquals(_api, api) || generation != _loginGeneration;
                    if (ReferenceEquals(_loginCts, cancellation)) _loginCts = null;
                }
                if (orphan) DisposeOrphanedApi(api);
                cancellation.Dispose();
            }
        });
    }

    private void HandleAuthenticationLost(SteamPrefillApi api, long generation, EResult? result)
    {
        lock (_lifecycle)
        {
            if (generation != _loginGeneration || !ReferenceEquals(_api, api)) return;
            _isLoggingIn = false;
            foreach (var run in _runs.Values) run.Progress.TryChooseTerminal("failed", "auth-lost");
            var lost = new SteamConnectionException(SteamFailure.AuthLost);
            // Only a dropped connection keeps the saved login usable without a person; a log-off
            // (for example the account signing in elsewhere) is not signed in again.
            _signOutCode = result is null || ConnectionWentAway(result.Value) ? lost.ErrorCode : null;
            _statusPublication = PublishStatusAsync(_statusPublication, "awaiting-login", lost.Message, _signOutCode);
            _ = _prefillOperation.CancelAllAndWaitAsync();
        }
    }

    // A sign-in that ends without signing in leaves the saved login usable unless it stopped at a
    // credential prompt or Steam refused the credentials (a wrong password, a refused code, or a
    // confirmation that never came), because a person is needed then. Any failure to reach Steam is
    // reported like a dropped connection. Called under _lifecycle.
    private string? SignOutCodeAfterUnfinishedSignIn(Exception? failure)
    {
        var steamRefused = failure switch
        {
            SteamKit2.Authentication.AuthenticationException refused => !ConnectionWentAway(refused.Result),
            System.Security.Authentication.AuthenticationException => true,
            _ => false
        };
        return steamRefused || _authProvider.CurrentChallengeId is not null
            ? null
            : new SteamConnectionException(SteamFailure.AuthLost).ErrorCode;
    }

    // Steam results that mean the connection or its server went away, as opposed to the account being
    // signed out (SteamKit2 marks TryAnotherCM and ServiceUnavailable log-offs as a bad server).
    private static bool ConnectionWentAway(EResult result) =>
        result is EResult.TryAnotherCM or EResult.ServiceUnavailable or EResult.NoConnection
            or EResult.Timeout or EResult.ConnectFailed or EResult.RemoteDisconnect;

    private async Task EndSessionAsync(bool erase, bool onlyLogin = false)
    {
        SteamPrefillApi? api;
        Task? login;
        CancellationTokenSource? cancellation;
        Task completion;
        lock (_lifecycle)
        {
            if (onlyLogin && !_isLoggingIn) return;
            ++_loginGeneration;
            _pendingAutoLoginChallenges.Clear();
            api = _api;
            _api = null;
            _isLoggingIn = false;
            cancellation = _loginCts;
            _loginCts = null;
            login = _loginTask;
            foreach (var run in _runs.Values) run.Progress.TryChooseTerminal("cancelled");
            completion = _prefillOperation.CancelAllAndWaitAsync();
            if (erase)
            {
                EraseAccountStore(_progress);
                _signOutCode = null;
            }
            else if (onlyLogin)
            {
                // The manager's cancel can arrive before the sign-in gives up by itself.
                _signOutCode = SignOutCodeAfterUnfinishedSignIn(null);
            }
            _statusPublication = PublishStatusAsync(_statusPublication, "awaiting-login", "Login required", _signOutCode);
            _authProvider.CancelPendingRequest();
        }
        try { cancellation?.Cancel(); }
        catch (ObjectDisposedException) { /* Login already completed. */ }
        await completion;
        if (api != null) DisposeOrphanedApi(api);
        if (login != null) await login;
        await _statusPublication;
    }

    private async Task<CommandResponse> HandleLogoutAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        await EndSessionAsync(true);
        return new CommandResponse { Id = request.Id, Success = true, Message = "Logged out successfully", CompletedAt = DateTime.UtcNow };
    }

    private async Task<CommandResponse> HandleCancelLoginAsync(CommandRequest request)
    {
        await EndSessionAsync(false, true);
        return new CommandResponse { Id = request.Id, Success = true, Message = "Login cancelled", CompletedAt = DateTime.UtcNow };
    }

    internal static DaemonCommandLane ClassifyCommand(string commandType)
    {
        return commandType.ToLowerInvariant() switch
        {
            "cancel-login" or "cancel-prefill" or "provide-credential" or "status" or "get-operation" or "shutdown"
                => DaemonCommandLane.Control,
            "get-owned-games" or "get-selected-apps" or "get-cache-info" or
                "get-selected-apps-status" or "check-cache-status"
                => DaemonCommandLane.Concurrent,
            _ => DaemonCommandLane.Serialized
        };
    }

    private Task<CommandResponse> HandleCancelPrefillAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        if (request.Parameters?.TryGetValue("operationId", out var operationId) == true)
        {
            lock (_lifecycle)
            {
                if (request.Parameters.GetValueOrDefault("daemonInstanceId") != _protocol.DaemonInstanceId)
                    return Task.FromResult(new CommandResponse { Id = request.Id, Success = false, Error = "instance-changed", ErrorCode = "instance-changed" });
                var operation = _prefillOperation.Cancel(operationId, _protocol.DaemonInstanceId);
                return Task.FromResult(new CommandResponse
                {
                    Id = request.Id,
                    Success = operation != null,
                    Data = operation,
                    Error = operation == null ? "operation-not-found" : null,
                    ErrorCode = operation == null ? "operation-not-found" : null
                });
            }
        }
        return Task.FromResult(new CommandResponse { Id = request.Id, Success = false, Error = "operation-not-found", ErrorCode = "operation-not-found" });
    }

    private CommandResponse HandleProvideCredential(CommandRequest request)
    {
        var challengeId = request.Parameters?.GetValueOrDefault("challengeId");
        var clientPublicKey = request.Parameters?.GetValueOrDefault("clientPublicKey");
        var encryptedCredential = request.Parameters?.GetValueOrDefault("encryptedCredential");
        var nonce = request.Parameters?.GetValueOrDefault("nonce");
        var tag = request.Parameters?.GetValueOrDefault("tag");

        if (string.IsNullOrEmpty(challengeId) || string.IsNullOrEmpty(clientPublicKey) ||
            string.IsNullOrEmpty(encryptedCredential) || string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(tag))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "Missing required credential parameters",
                CompletedAt = DateTime.UtcNow
            };
        }

        var response = new EncryptedCredentialResponse
        {
            ChallengeId = challengeId,
            ClientPublicKey = clientPublicKey,
            EncryptedCredential = encryptedCredential,
            Nonce = nonce,
            Tag = tag
        };

        // Only report success when the credential matched a live pending challenge. A dropped
        // credential (no pending challenge, or a stale
        // challenge id from a replaced login session) must surface as a failure so the manager can
        // detect the desync instead of celebrating a credential the daemon silently discarded.
        var accepted = _authProvider.ReceiveCredential(response);
        if (!accepted)
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "No matching login challenge is pending for this credential",
                CompletedAt = DateTime.UtcNow
            };
        }

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Credential received",
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleGetAutoLoginChallenge(CommandRequest request)
    {
        lock (_lifecycle)
        {
            using var ecdh = System.Security.Cryptography.ECDiffieHellman.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var parameters = ecdh.ExportParameters(true);

            // Export public key in uncompressed point format
            var serverPublicKey = new byte[65];
            serverPublicKey[0] = 0x04; // Uncompressed point indicator
            Array.Copy(parameters.Q.X!, 0, serverPublicKey, 1, 32);
            Array.Copy(parameters.Q.Y!, 0, serverPublicKey, 33, 32);

            var challengeId = Guid.NewGuid().ToString("N");
            var expiresAt = DateTime.UtcNow.AddMinutes(5);

            // Store challenge data
            var challengeData = new AutoLoginChallengeData
            {
                ChallengeId = challengeId,
                ServerPrivateKey = parameters,
                ServerPublicKey = serverPublicKey,
                Generation = _loginGeneration,
                ExpiresAt = expiresAt
            };

            _pendingAutoLoginChallenges[challengeId] = challengeData;

            // Clean up expired challenges
            var expiredChallenges = _pendingAutoLoginChallenges
                .Where(kvp => kvp.Value.ExpiresAt < DateTime.UtcNow)
                .Select(kvp => kvp.Key)
                .ToList();
            foreach (var expiredId in expiredChallenges)
            {
                _pendingAutoLoginChallenges.Remove(expiredId);
            }

            _progress.OnLog(LogLevel.Info, $"Auto-login challenge created: {challengeId}");

            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = new CredentialChallenge
                {
                    ChallengeId = challengeId,
                    CredentialType = "auto-login",
                    ServerPublicKey = System.Convert.ToBase64String(serverPublicKey),
                    CreatedAt = DateTime.UtcNow,
                    ExpiresAt = expiresAt
                },
                CompletedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<CommandResponse> HandleProvideAutoLoginAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        var challengeId = request.Parameters?.GetValueOrDefault("challengeId");
        var clientPublicKey = request.Parameters?.GetValueOrDefault("clientPublicKey");
        var encryptedCredential = request.Parameters?.GetValueOrDefault("encryptedCredential");
        var nonce = request.Parameters?.GetValueOrDefault("nonce");
        var tag = request.Parameters?.GetValueOrDefault("tag");

        if (string.IsNullOrEmpty(challengeId) || string.IsNullOrEmpty(clientPublicKey) ||
            string.IsNullOrEmpty(encryptedCredential) || string.IsNullOrEmpty(nonce) || string.IsNullOrEmpty(tag))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "Missing required auto-login parameters",
                CompletedAt = DateTime.UtcNow
            };
        }

        AutoLoginChallengeData? challengeData;
        lock (_lifecycle)
        {
            // Get challenge from dictionary
            if (!_pendingAutoLoginChallenges.TryGetValue(challengeId, out challengeData))
            {
                return new CommandResponse
                {
                    Id = request.Id,
                    Success = false,
                    Error = "Invalid or expired challenge ID",
                    CompletedAt = DateTime.UtcNow
                };
            }

            // Validate not expired
            if (challengeData.ExpiresAt < DateTime.UtcNow)
            {
                _pendingAutoLoginChallenges.Remove(challengeId);
                return new CommandResponse
                {
                    Id = request.Id,
                    Success = false,
                    Error = "Challenge has expired",
                    CompletedAt = DateTime.UtcNow
                };
            }

            // Remove from dictionary (one-time use)
            _pendingAutoLoginChallenges.Remove(challengeId);

        }

        try
        {
            // Decrypt using ECDH + AES-GCM (same as SecureCredentialExchange)
            var clientPublicKeyBytes = System.Convert.FromBase64String(clientPublicKey);

            // Recreate server ECDH instance
            using var serverEcdh = System.Security.Cryptography.ECDiffieHellman.Create();
            serverEcdh.ImportParameters(challengeData.ServerPrivateKey);

            // Import client public key
            using var clientEcdh = System.Security.Cryptography.ECDiffieHellman.Create();
            var clientParams = new System.Security.Cryptography.ECParameters
            {
                Curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
                Q = new System.Security.Cryptography.ECPoint
                {
                    X = clientPublicKeyBytes.AsSpan(1, 32).ToArray(),
                    Y = clientPublicKeyBytes.AsSpan(33, 32).ToArray()
                }
            };
            clientEcdh.ImportParameters(clientParams);

            // Derive shared secret
            var sharedSecret = serverEcdh.DeriveKeyMaterial(clientEcdh.PublicKey);

            // Derive AES key from shared secret using HKDF
            var aesKey = System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                sharedSecret,
                32, // 256-bit key
                System.Text.Encoding.UTF8.GetBytes(challengeId),
                System.Text.Encoding.UTF8.GetBytes("SteamPrefill-Credential-Encryption"));

            // Decrypt with AES-GCM
            var nonceBytes = System.Convert.FromBase64String(nonce);
            var ciphertext = System.Convert.FromBase64String(encryptedCredential);
            var tagBytes = System.Convert.FromBase64String(tag);

            var plaintext = new byte[ciphertext.Length];
            using var aesGcm = new System.Security.Cryptography.AesGcm(aesKey, 16);
            aesGcm.Decrypt(nonceBytes, ciphertext, tagBytes, plaintext);

            var decryptedJson = System.Text.Encoding.UTF8.GetString(plaintext);

            // Securely clear sensitive data
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(sharedSecret);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(aesKey);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);

            // Parse JSON: {"username":"...", "refreshToken":"..."}
            var autoLoginData = JsonSerializer.Deserialize(decryptedJson, DaemonSerializationContext.Default.AutoLoginCredentials);
            if (autoLoginData == null || string.IsNullOrEmpty(autoLoginData.Username) || string.IsNullOrEmpty(autoLoginData.RefreshToken))
            {
                return new CommandResponse
                {
                    Id = request.Id,
                    Success = false,
                    Error = "Invalid auto-login credential format",
                    CompletedAt = DateTime.UtcNow
                };
            }

            _progress.OnLog(LogLevel.Info, $"Auto-login credentials received for user: {autoLoginData.Username}");

            Task? login;
            SteamPrefillApi? acceptedApi;
            long acceptedGeneration;
            lock (_lifecycle)
            {
                if (challengeData.Generation != _loginGeneration)
                    return new CommandResponse
                    {
                        Id = request.Id,
                        Success = false,
                        Error = "The sign-in attempt has ended. Sign in again.",
                        CompletedAt = DateTime.UtcNow
                    };
                if (!_isLoggedIn && !_isLoggingIn) StartLogin(autoLoginData.Username, autoLoginData.RefreshToken);
                login = _loginTask;
                acceptedApi = _api;
                acceptedGeneration = _loginGeneration;
            }
            if (login != null) await login.WaitAsync(cancellationToken);
            lock (_lifecycle)
            {
                var ready = acceptedGeneration == _loginGeneration && ReferenceEquals(acceptedApi, _api) && _isLoggedIn;
                return new CommandResponse
                {
                    Id = request.Id,
                    Success = ready,
                    Message = ready ? "Auto-login successful" : "Steam sign-in did not complete. Sign in again.",
                    RequiresLogin = !ready,
                    CompletedAt = DateTime.UtcNow
                };
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
    }

    private CommandResponse HandleStatus(CommandRequest request)
    {
        lock (_lifecycle)
        {
            PruneRuns();
            var ready = _api?.IsInitialized == true;
            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = new StatusData
                {
                    IsLoggedIn = ready,
                    IsInitialized = ready,
                    AuthExpiryUtc = ready ? _api?.AuthExpiryUtc : null,
                    Username = ready ? _api?.Username : null
                    ,
                    ErrorCode = ready ? null : _signOutCode,
                    ProtocolVersion = PrefillProtocol.Version,
                    Features = [.. PrefillProtocol.Features, "cacheStatusAppIds", "cacheStatusV2"],
                    DaemonInstanceId = _protocol.DaemonInstanceId,
                    MaxConcurrentRuns = _protocol.MaxConcurrentRuns,
                    MaxConcurrentRequests = _protocol.MaxConcurrentRequests,
                    ActiveOperations = _prefillOperation.GetActiveOperations(),
                    RecentOperations = _prefillOperation.GetRecentOperations()
                },
                CompletedAt = DateTime.UtcNow
            };
        }
    }

    private async Task<CommandResponse> HandleGetOwnedGamesAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        var api = EnsureLoggedIn();
        var games = await api.GetOwnedGamesAsync(cancellationToken);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = games,
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleGetSelectedApps(CommandRequest request)
    {
        var api = EnsureLoggedIn();
        var selected = api.GetSelectedApps();

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = selected,
            CompletedAt = DateTime.UtcNow
        };
    }

    private CommandResponse HandleSetSelectedApps(CommandRequest request)
    {
        var api = EnsureLoggedIn();

        var appIdsJson = request.Parameters?.GetValueOrDefault("appIds");
        if (string.IsNullOrEmpty(appIdsJson))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "appIds parameter required",
                CompletedAt = DateTime.UtcNow
            };
        }

        // Lancache-manager may send Steam app IDs as numbers or strings.
        // Parse a mixed array safely so string payloads don't throw before fallback logic can run.
        var appIds = new List<uint>();
        var rawElementCount = 0;
        using (var appIdsDoc = JsonDocument.Parse(appIdsJson))
        {
            if (appIdsDoc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return new CommandResponse
                {
                    Id = request.Id,
                    Success = false,
                    Error = "appIds must be a JSON array",
                    CompletedAt = DateTime.UtcNow
                };
            }

            foreach (var element in appIdsDoc.RootElement.EnumerateArray())
            {
                rawElementCount++;
                if (element.ValueKind == JsonValueKind.Number && element.TryGetUInt32(out var numericAppId))
                {
                    appIds.Add(numericAppId);
                    continue;
                }

                if (element.ValueKind == JsonValueKind.String &&
                    uint.TryParse(element.GetString(), out var stringAppId))
                {
                    appIds.Add(stringAppId);
                }
            }
        }

        // An empty array is a valid request: it clears the current selection. Only reject when
        // the caller sent a non-empty array that contained no parseable Steam app IDs.
        if (appIds.Count == 0 && rawElementCount > 0)
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = false,
                Error = "No valid Steam app IDs provided",
                CompletedAt = DateTime.UtcNow
            };
        }

        api.SetSelectedApps(appIds);
        _progress.OnLog(LogLevel.Info, $"Set {appIds.Count} selected apps");

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Message = "Apps selected",
            CompletedAt = DateTime.UtcNow
        };
    }

    private Task<CommandResponse> HandlePrefillAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        if (request.Parameters?.GetValueOrDefault("protocolVersion") != "2")
            return Task.FromResult(new CommandResponse { Id = request.Id, Success = false, ErrorCode = "daemon-outdated", Error = "This daemon only accepts protocol version 2.", CompletedAt = DateTime.UtcNow });
        return HandleRunAsync(request, cancellationToken);
    }

    private CommandResponse HandleOperation(CommandRequest request)
    {
        lock (_lifecycle)
        {
            PruneRuns();
            var parameters = request.Parameters;
            if (parameters?.GetValueOrDefault("daemonInstanceId") != _protocol.DaemonInstanceId)
                return new CommandResponse { Id = request.Id, Error = "instance-changed", ErrorCode = "instance-changed" };
            var operationId = parameters.GetValueOrDefault("operationId");
            if (string.IsNullOrWhiteSpace(operationId))
                return new CommandResponse { Id = request.Id, Error = "operation-not-found", ErrorCode = "operation-not-found" };
            var offset = parameters.TryGetValue("offset", out var offsetText) ? int.Parse(offsetText, System.Globalization.CultureInfo.InvariantCulture) : 0;
            var limit = parameters.TryGetValue("limit", out var limitText) ? int.Parse(limitText, System.Globalization.CultureInfo.InvariantCulture) : 100;
            var operation = _prefillOperation.GetOperation(operationId, offset, limit);
            return new CommandResponse
            {
                Id = request.Id,
                Success = operation != null,
                Data = operation == null ? null : new PrefillPage
                {
                    Operation = operation.Operation,
                    Options = operation.Options,
                    SelectionResolved = operation.SelectionResolved,
                    TotalItems = operation.TotalItems,
                    NextOffset = operation.NextOffset,
                    Items = operation.Items.Select(item => new PrefillItem
                    {
                        AppId = item.AppId,
                        Name = item.Name,
                        State = item.State,
                        Result = item.Result,
                        Reason = item.Reason,
                        Sequence = item.Sequence,
                        BytesTransferred = item.BytesTransferred,
                        TotalBytes = item.TotalBytes,
                        Depots = _runs.GetValueOrDefault(operationId)?.Depots.GetValueOrDefault(item.AppId)
                    }).ToArray()
                },
                Error = operation == null ? "operation-not-found" : null,
                ErrorCode = operation == null ? "operation-not-found" : null
            };
        }
    }

    private Task<CommandResponse> HandleRunAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        lock (_lifecycle)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var api = EnsureLoggedIn();
            PruneRuns();
            var parameters = request.Parameters!;
            if (parameters.GetValueOrDefault("daemonInstanceId") != _protocol.DaemonInstanceId)
                return Task.FromResult(new CommandResponse { Id = request.Id, Error = "instance-changed", ErrorCode = "instance-changed" });
            if (!Guid.TryParse(request.Id, out _))
                return Task.FromResult(new CommandResponse { Id = request.Id, Error = "A valid operation ID is required." });
            var options = new PrefillOptions
            {
                DownloadAllOwnedGames = bool.TryParse(parameters.GetValueOrDefault("all"), out var all) && all,
                PrefillRecentGames = bool.TryParse(parameters.GetValueOrDefault("recent"), out var recent) && recent,
                PrefillRecentlyPurchased = bool.TryParse(parameters.GetValueOrDefault("recently_purchased"), out var purchased) && purchased,
                PrefillTopGames = parameters.TryGetValue("top", out var top) ? int.Parse(top, System.Globalization.CultureInfo.InvariantCulture) : null,
                Force = bool.TryParse(parameters.GetValueOrDefault("force"), out var force) && force,
                MaxConcurrency = parameters.TryGetValue("maxConcurrency", out var maximum) ? int.Parse(maximum, System.Globalization.CultureInfo.InvariantCulture) : _protocol.MaxConcurrentRequests
            };
            var presets = new List<string>();
            if (options.DownloadAllOwnedGames) presets.Add("all");
            if (options.PrefillRecentGames) presets.Add("recent");
            if (options.PrefillRecentlyPurchased) presets.Add("recently_purchased");
            if (options.PrefillTopGames != null) presets.Add("top");
            if (presets.Count > 1 || options.PrefillTopGames <= 0)
                return Task.FromResult(new CommandResponse { Id = request.Id, Error = "Conflicting or invalid selection preset." });
            List<string>? appIds = null;
            if (parameters.TryGetValue("appIds", out var selection))
            {
                using var document = JsonDocument.Parse(selection);
                appIds = document.RootElement.EnumerateArray().Select(element =>
                    (element.ValueKind == JsonValueKind.Number ? element.GetUInt32() : uint.Parse(element.GetString()!, System.Globalization.CultureInfo.InvariantCulture))
                    .ToString(System.Globalization.CultureInfo.InvariantCulture)).ToList();
            }
            if (parameters.TryGetValue("os", out var operatingSystems))
                options.OperatingSystems = operatingSystems.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(value => OperatingSystem.FromValue(value.ToLowerInvariant())).ToList();
            var cacheSnapshot = parameters.TryGetValue("cachedDepots", out var cached);
            var cachedDepots = cacheSnapshot
                ? JsonSerializer.Deserialize(cached ?? throw new ArgumentException("Invalid cached depots."), DaemonSerializationContext.Default.ListCachedDepotInput) ?? throw new ArgumentException("Invalid cached depots.")
                : new List<CachedDepotInput>();
            var captured = _protocol.Capture(new RunOptions
            {
                AppIds = appIds,
                Selection = presets.FirstOrDefault() ?? "selected",
                Force = options.Force,
                OperatingSystems = options.OperatingSystems.Select(os => os.Value).ToArray(),
                MaxConcurrency = options.MaxConcurrency!.Value,
                TopCount = options.PrefillTopGames,
                CachedDepots = cachedDepots.Select(depot => $"{depot.DepotId}:{depot.ManifestId}").Order(StringComparer.Ordinal).ToArray()
            });
            var progress = new RunProgress(request.Id, _protocol.DaemonInstanceId, captured, PublishRunAsync);
            var run = new PrefillRun(captured, progress, _budget, _claims, cacheSnapshot);
            var sink = new SocketProgress(run: run, sync: _lifecycle, enableDebugLogs: AppConfig.DebugLogs);
            var admission = _prefillOperation.StartAsync(request.Id, $"{PrefillProtocol.Fingerprint(captured)}:{cacheSnapshot}", progress, async token =>
            {
                PrefillRun.Current.Value = run;
                try
                {
                    var result = await api.PrefillAsync(options, token, sink);
                    if (!result.Success)
                    {
                        progress.TryChooseTerminal("failed", result.ErrorCode);
                        System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(result.Exception ?? new InvalidOperationException(result.ErrorMessage)).Throw();
                    }
                    token.ThrowIfCancellationRequested();
                    progress.TryChooseTerminal("completed");
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    progress.TryChooseTerminal("cancelled");
                    throw;
                }
                catch (Exception exception)
                {
                    progress.TryChooseTerminal("failed", (exception as SteamConnectionException)?.ErrorCode);
                    throw;
                }
                finally
                {
                    await run.CompleteAsync();
                    PrefillRun.Current.Value = null;
                }
            }, _cts.Token).GetAwaiter().GetResult();
            if (admission.Accepted && !admission.Replayed) _runs.Add(request.Id, run);
            return Task.FromResult(new CommandResponse
            {
                Id = request.Id,
                Success = admission.Accepted,
                Error = admission.Error,
                ErrorCode = admission.Error,
                Data = admission.Accepted ? new PrefillStart
                {
                    RunId = request.Id,
                    DaemonInstanceId = _protocol.DaemonInstanceId,
                    State = admission.Replayed ? admission.Operation!.State : "started",
                    Operation = admission.Operation
                } : null
            });
        }
    }

    private Task PublishRunAsync(RunSnapshot snapshot, CancellationToken cancellationToken)
    {
        var update = ToProgress(snapshot);
        lock (_lifecycle)
            update.Depots = snapshot.CurrentItem == null ? null : _runs.GetValueOrDefault(snapshot.OperationId)?.Depots.GetValueOrDefault(snapshot.CurrentItem.AppId);
        return _socketServer.BroadcastProgressAsync(new ProgressEvent(update), cancellationToken);
    }

    private void PruneRuns()
    {
        var retained = _prefillOperation.GetActiveOperations().Concat(_prefillOperation.GetRecentOperations())
            .Select(run => run.OperationId).ToHashSet(StringComparer.Ordinal);
        foreach (var id in _runs.Keys.Where(id => !retained.Contains(id)).ToArray()) _runs.Remove(id);
    }

    internal static PrefillProgressUpdate ToProgress(RunSnapshot snapshot)
    {
        var item = snapshot.CurrentItem;
        return new PrefillProgressUpdate
        {
            OperationId = snapshot.OperationId,
            DaemonInstanceId = snapshot.DaemonInstanceId,
            Sequence = snapshot.Sequence,
            StartedAt = snapshot.StartedAt,
            UpdatedAt = snapshot.UpdatedAt.UtcDateTime,
            State = snapshot.State is "completed" or "failed" or "cancelled" or "cancelling" ? snapshot.State :
                item?.Result == "already_cached" ? "already_cached" : item?.Result != null ? "app_completed" : snapshot.State,
            CurrentAppId = item == null ? 0 : uint.Parse(item.AppId, System.Globalization.CultureInfo.InvariantCulture),
            CurrentAppName = item?.Name,
            Result = item?.Result,
            Reason = snapshot.Reason ?? item?.Reason,
            BytesDownloaded = item?.BytesTransferred ?? 0,
            TotalBytes = item?.TotalBytes ?? 0,
            TotalBytesTransferred = snapshot.BytesTransferred,
            TotalApps = snapshot.TotalApps,
            UpdatedApps = snapshot.CompletedApps,
            AlreadyUpToDate = snapshot.CachedApps,
            FailedApps = snapshot.FailedApps,
            SkippedApps = snapshot.SkippedApps,
            CancelledApps = snapshot.CancelledApps,
            TotalTime = snapshot.UpdatedAt - snapshot.StartedAt,
            ErrorCode = snapshot.State == "failed" ? snapshot.Reason : null,
            RequiresLogin = snapshot.Reason == "auth-lost" ? true : null
        };
    }

    private CommandResponse HandleClearCache(CommandRequest request)
    {
        lock (_lifecycle)
        {
            if (_prefillOperation.IsRunning) return new CommandResponse { Id = request.Id, Success = false, Error = "Active operations must drain before clearing cache." };
            var result = SteamPrefillApi.ClearCache();
            if (result.Success && _api != null && _isLoggedIn)
            {
                _api.ClearAppInfoCache();
            }

            return new CommandResponse
            {
                Id = request.Id,
                Success = result.Success,
                Data = result,
                Message = result.Message,
                CompletedAt = DateTime.UtcNow
            };
        }
    }

    private CommandResponse HandleGetCacheInfo(CommandRequest request)
    {
        var info = SteamPrefillApi.GetCacheInfo();

        return new CommandResponse
        {
            Id = request.Id,
            Success = info.Success,
            Data = info,
            Message = info.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private async Task<CommandResponse> HandleGetSelectedAppsStatusAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        var api = EnsureLoggedIn();

        var operatingSystems = ReadOperatingSystems(request);
        if (operatingSystems.Count > 0)
            api.UpdateDownloadOptions(operatingSystems: operatingSystems);

        // Parse optional cachedDepots
        List<CachedDepotInput>? cachedDepots = null;
        var cachedDepotsJson = request.Parameters?.GetValueOrDefault("cachedDepots");
        if (!string.IsNullOrEmpty(cachedDepotsJson))
        {
            cachedDepots = JsonSerializer.Deserialize(cachedDepotsJson, DaemonSerializationContext.Default.ListCachedDepotInput);
        }

        var status = await api.GetSelectedAppsStatusAsync(cachedDepots, cancellationToken);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = status,
            Message = status.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private async Task<CommandResponse> HandleCheckCacheStatusAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        var api = EnsureLoggedIn();
        var operatingSystems = ReadOperatingSystems(request);

        if (request.Parameters?.TryGetValue("cacheStatusVersion", out var versionValue) == true)
        {
            if (!int.TryParse(
                    versionValue,
                    System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var version)
                || version != 2)
            {
                throw new JsonException("cacheStatusVersion must be 2.");
            }

            if (!request.Parameters.TryGetValue("appIds", out var appIdsJson)
                || !request.Parameters.TryGetValue("cachedDepots", out var currentCachedDepotsJson)
                || !request.Parameters.TryGetValue("scope", out var scopeJson)
                || !request.Parameters.TryGetValue("expiresAtUtc", out var expiresAtUtcValue))
            {
                throw new JsonException("Version 2 cache status fields are required.");
            }

            var appIds = JsonSerializer.Deserialize(appIdsJson, DaemonSerializationContext.Default.ListUInt32)
                ?? throw new JsonException("appIds must be a JSON array.");
            var currentCachedDepots = JsonSerializer.Deserialize(
                currentCachedDepotsJson,
                DaemonSerializationContext.Default.ListCachedDepotInput)
                ?? throw new JsonException("cachedDepots must be a JSON array.");
            using var scopeDocument = JsonDocument.Parse(scopeJson);
            if (scopeDocument.RootElement.ValueKind != JsonValueKind.Array)
                throw new JsonException("scope must be a JSON array.");
            foreach (var item in scopeDocument.RootElement.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object
                    || !item.TryGetProperty("authority", out var authorityElement)
                    || authorityElement.ValueKind != JsonValueKind.String
                    || authorityElement.GetString() is not ("Absent" or "Empty" or "Snapshot"))
                {
                    throw new JsonException("scope authority must be an exact cache authority name.");
                }
            }
            var scope = JsonSerializer.Deserialize(scopeJson, DaemonSerializationContext.Default.ListCacheAppScope)
                ?? throw new JsonException("scope must be a JSON array.");

            if (appIds.Any(appId => appId == 0) || appIds.Distinct().Count() != appIds.Count)
                throw new JsonException("appIds must contain distinct positive IDs.");
            if (currentCachedDepots.Any(depot => depot.AppId == 0 || depot.DepotId == 0 || depot.ManifestId == 0))
                throw new JsonException("cachedDepots contains an invalid ID.");
            if (scope.Any(item => item.AppId == 0 || !item.Authority.HasValue)
                || scope.Select(item => item.AppId).Distinct().Count() != scope.Count
                || scope.Count != appIds.Count
                || !scope.Select(item => item.AppId).ToHashSet().SetEquals(appIds))
            {
                throw new JsonException("scope must contain one authority for every requested app.");
            }
            if (!DateTimeOffset.TryParseExact(
                    expiresAtUtcValue,
                    "O",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind,
                    out var expiresAtUtc))
            {
                throw new JsonException("expiresAtUtc must use round-trip ISO 8601 format.");
            }
            var currentStatus = await api.CheckCacheStatusAsync(
                currentCachedDepots,
                cancellationToken,
                appIds,
                scope,
                expiresAtUtc,
                version,
                operatingSystems);

            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = currentStatus,
                Message = currentStatus.Message,
                CompletedAt = DateTime.UtcNow
            };
        }

        if (request.Parameters?.ContainsKey("appIds") == true)
        {
            var appIdsJson = request.Parameters["appIds"];
            if (!request.Parameters.TryGetValue("cachedDepots", out var currentCachedDepotsJson))
            {
                throw new JsonException("cachedDepots is required when appIds is supplied.");
            }

            var appIds = JsonSerializer.Deserialize(appIdsJson, DaemonSerializationContext.Default.ListUInt32)
                ?? throw new JsonException("appIds must be a JSON array.");
            var currentCachedDepots = JsonSerializer.Deserialize(
                currentCachedDepotsJson,
                DaemonSerializationContext.Default.ListCachedDepotInput)
                ?? throw new JsonException("cachedDepots must be a JSON array.");
            var currentStatus = await api.CheckCacheStatusAsync(
                currentCachedDepots,
                cancellationToken,
                appIds,
                operatingSystems: operatingSystems);

            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = currentStatus,
                Message = currentStatus.Message,
                CompletedAt = DateTime.UtcNow
            };
        }

        var cachedDepotsJson = request.Parameters?.GetValueOrDefault("cachedDepots");
        if (string.IsNullOrEmpty(cachedDepotsJson))
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = new CacheStatusResult { Apps = new List<AppCacheStatus>(), Message = "No cached depots provided" },
                Message = "No cached depots provided",
                CompletedAt = DateTime.UtcNow
            };
        }

        var cachedDepots = JsonSerializer.Deserialize(cachedDepotsJson, DaemonSerializationContext.Default.ListCachedDepotInput);
        if (cachedDepots == null || cachedDepots.Count == 0)
        {
            return new CommandResponse
            {
                Id = request.Id,
                Success = true,
                Data = new CacheStatusResult { Apps = new List<AppCacheStatus>(), Message = "No cached depots provided" },
                Message = "No cached depots provided",
                CompletedAt = DateTime.UtcNow
            };
        }

        var status = await api.CheckCacheStatusAsync(
            cachedDepots,
            cancellationToken,
            operatingSystems: operatingSystems);

        return new CommandResponse
        {
            Id = request.Id,
            Success = true,
            Data = status,
            Message = status.Message,
            CompletedAt = DateTime.UtcNow
        };
    }

    private static List<OperatingSystem> ReadOperatingSystems(CommandRequest request)
    {
        var operatingSystems = new List<OperatingSystem>();
        var value = request.Parameters?.GetValueOrDefault("os");
        if (string.IsNullOrWhiteSpace(value)) return operatingSystems;
        foreach (var name in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (OperatingSystem.TryFromValue(name.ToLowerInvariant(), out var operatingSystem))
                operatingSystems.Add(operatingSystem);
        }
        return operatingSystems;
    }

    private async Task<CommandResponse> HandleShutdownAsync(CommandRequest request, CancellationToken cancellationToken)
    {
        await EndSessionAsync(false);
        return new CommandResponse { Id = request.Id, Success = true, Message = "Shutdown complete", CompletedAt = DateTime.UtcNow };
    }

    private SteamPrefillApi EnsureLoggedIn()
    {
        lock (_lifecycle)
        {
            if (_api?.IsInitialized != true) throw new SteamConnectionException(SteamFailure.AuthLost);
            return _api;
        }
    }

    private static void DisposeOrphanedApi(SteamPrefillApi api)
    {
        try
        {
            api.Dispose();
        }
        catch (Exception ex) { FileLogger.LogException("Steam session cleanup failed", ex); }

    }

    /// <summary>Removes credentials only for an accepted explicit logout.</summary>
    private static void EraseAccountStore(IPrefillProgress? progress = null)
    {
        TryDeleteAccountStoreFile(AppConfig.AccountSettingsStorePath, "Account credentials", progress);
        TryDeleteAccountStoreFile(TokenStorageEncryption.KeyFilePath, "Storage key", progress);
    }

    private static void TryDeleteAccountStoreFile(string path, string label, IPrefillProgress? progress)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
                progress?.OnLog(LogLevel.Info, $"{label} removed from disk");
            }
        }
        catch (Exception ex)
        {
            FileLogger.LogException($"Could not remove {label.ToLowerInvariant()} from disk", ex);
        }
    }

    private async Task PublishStatusAsync(Task previous, string status, string message, string? errorCode = null)
    {
        var generation = _loginGeneration;
        await Task.Yield();
        try { await previous; }
        catch (Exception ex) { FileLogger.LogException("Auth state publication failed", ex); }
        lock (_lifecycle)
        {
            if (generation != _loginGeneration || (status == "logged-in") != _isLoggedIn) return;
        }
        await BroadcastStatusAsync(status, message, errorCode);
    }

    private async Task BroadcastStatusAsync(string status, string message, string? errorCode = null)
    {
        var statusEvent = new AuthStateEvent(status, message, errorCode);
        await _socketServer.BroadcastAuthStateAsync(statusEvent);
    }

    public void Dispose()
    {
        lock (_lifecycle)
        {
            if (_disposed) return;
            _disposed = true;
        }

        _cts.Cancel();
        EndSessionAsync(false).GetAwaiter().GetResult();
        _loginCts?.Dispose();
        _prefillOperation.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _budget.Dispose();
        _cts.Dispose();
        _api?.Dispose();
        _authProvider.Dispose();
        _socketServer.DisposeAsync().AsTask().GetAwaiter().GetResult();

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Progress implementation that broadcasts updates via socket.
    /// </summary>
    internal sealed class SocketProgress : IPrefillProgress
    {
        private readonly DaemonLogSink _logSink;
        private readonly object _sync;
        private readonly PrefillRun? _run;

        internal SocketProgress(
            bool enableDebugLogs = false,
            Action<string>? logWriter = null,
            object? sync = null, PrefillRun? run = null)
        {
            _sync = sync ?? new object();
            _run = run;
            _logSink = new DaemonLogSink(
                logWriter ?? Console.WriteLine,
                enableDebugLogs ? DaemonLogLevel.Debug : DaemonLogLevel.Info);
        }

        public void OnLog(LogLevel level, string message)
        {
            var prefix = level switch
            {
                LogLevel.Debug => "[DEBUG]",
                LogLevel.Info => "[INFO]",
                LogLevel.Warning => "[WARN]",
                LogLevel.Error => "[ERROR]",
                _ => "[LOG]"
            };
            var daemonLevel = level switch
            {
                LogLevel.Debug => DaemonLogLevel.Debug,
                LogLevel.Info => DaemonLogLevel.Info,
                LogLevel.Warning => DaemonLogLevel.Warning,
                LogLevel.Error => DaemonLogLevel.Error,
                _ => DaemonLogLevel.Info
            };
            _logSink.Write(daemonLevel, $"{DateTime.UtcNow:HH:mm:ss} {prefix} {message}");
        }

        public void OnOperationStarted(string operationName)
            => OnLog(LogLevel.Info, $"Starting: {operationName}");

        public void OnOperationCompleted(string operationName, TimeSpan elapsed)
            => OnLog(LogLevel.Info, $"Completed: {operationName} ({elapsed.TotalSeconds:F2}s)");

        public void OnAppStarted(AppDownloadInfo app)
        {
            if (_run != null)
            {
                lock (_sync)
                {
                    if (_run.Progress.Terminal != null) return;
                    if (app.Depots != null) _run.Depots[app.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture)] = app.Depots
                        .Select(depot => new DepotManifestUpdateInfo { DepotId = depot.DepotId, ManifestId = depot.ManifestId, TotalBytes = depot.TotalBytes }).ToList();
                    _run.Progress.UpdateItem(new RunItemSnapshot
                    {
                        AppId = app.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        Name = app.Name,
                        State = "downloading",
                        TotalBytes = app.TotalBytes
                    });
                }
            }
        }

        public void OnDownloadProgress(DownloadProgressInfo progress)
        {
            if (_run != null)
            {
                lock (_sync)
                {
                    _run.Progress.UpdateItem(new RunItemSnapshot
                    {
                        AppId = progress.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        Name = progress.AppName,
                        State = "downloading",
                        TotalBytes = progress.TotalBytes,
                        BytesTransferred = progress.BytesDownloaded
                    });
                }
            }
        }

        public void OnAppCompleted(AppDownloadInfo app, AppDownloadResult result)
        {
            if (_run != null)
            {
                lock (_sync)
                {
                    if (_run.Progress.Terminal != null) return;
                    var appId = app.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    if (app.Depots != null) _run.Depots[appId] = app.Depots
                        .Select(depot => new DepotManifestUpdateInfo { DepotId = depot.DepotId, ManifestId = depot.ManifestId, TotalBytes = depot.TotalBytes }).ToList();
                    var outcome = result switch
                    {
                        AppDownloadResult.Success => "success",
                        AppDownloadResult.AlreadyUpToDate => "already_cached",
                        AppDownloadResult.Failed => "failed",
                        _ => "skipped"
                    };
                    _run.Progress.UpdateItem(new RunItemSnapshot
                    {
                        AppId = appId,
                        Name = app.Name,
                        State = "completed",
                        Result = outcome,
                        Reason = app.Reason,
                        TotalBytes = app.TotalBytes,
                        BytesTransferred = _run.Bytes(appId)
                    });
                }
            }
        }

        public void OnPrefillCompleted(PrefillSummary summary) { }

        public void OnError(string message, Exception? exception = null)
        {
            if (_run != null)
            {
                _run.Progress.TryChooseTerminal("failed", (exception as SteamConnectionException)?.ErrorCode);
                if (exception != null) FileLogger.LogException(message, exception);
                return;
            }
            if (exception != null) FileLogger.LogException(message, exception);
            else OnLog(LogLevel.Error, message);
        }
    }

}
