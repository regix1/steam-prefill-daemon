#nullable enable

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace SteamPrefill.Api;

/// <summary>
/// Unix Domain Socket server for IPC with lancache-manager.
/// Provides reliable, low-latency bidirectional communication.
///
/// Protocol:
/// - All messages are JSON with a 4-byte little-endian length prefix
/// - Client sends CommandRequest, receives CommandResponse
/// - Server can send unsolicited SocketEvent messages (progress, challenges, etc.)
///
/// Security:
/// - Socket file permissions: 0660 (owner/group only)
/// - Optional shared secret via PREFILL_SOCKET_SECRET environment variable
/// - Credential encryption: ECDH + AES-GCM
/// - Challenge expiration: 5 minutes
/// </summary>
public sealed class SocketServer : IAsyncDisposable
{
    private readonly string _socketPath;
    private readonly IPrefillProgress _progress;
    private readonly string? _sharedSecret;
    private readonly CancellationTokenSource _cts = new();
    private Socket? _listener;
    private readonly ConcurrentDictionary<string, ConnectedClient> _clients = new();
    private Task? _acceptTask;
    private bool _disposed;

    /// <summary>
    /// Called when a command is received. Return the response to send back.
    /// </summary>
    public Func<CommandRequest, CancellationToken, Task<CommandResponse>>? OnCommand { get; set; }

    /// <summary>
    /// Called when a client connects.
    /// </summary>
    public event Action<string>? OnClientConnected;

    /// <summary>
    /// Called when a client disconnects.
    /// </summary>
    public event Action<string>? OnClientDisconnected;

    public SocketServer(string socketPath, IPrefillProgress? progress = null)
    {
        _socketPath = socketPath;
        _progress = progress ?? NullProgress.Instance;

        // Optional shared secret for additional security
        _sharedSecret = Environment.GetEnvironmentVariable("PREFILL_SOCKET_SECRET");
        if (!string.IsNullOrEmpty(_sharedSecret))
        {
            _progress.OnLog(LogLevel.Info, "Socket authentication enabled via PREFILL_SOCKET_SECRET");
        }
    }

    /// <summary>
    /// Start listening for connections.
    /// </summary>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        // Remove existing socket file if any (from previous crash)
        if (File.Exists(_socketPath))
        {
            try
            {
                File.Delete(_socketPath);
                _progress.OnLog(LogLevel.Debug, $"Removed stale socket file: {_socketPath}");
            }
            catch (Exception ex)
            {
                _progress.OnLog(LogLevel.Warning, $"Could not remove stale socket file: {ex.Message}");
            }
        }

        // Ensure directory exists with secure permissions
        var dir = Path.GetDirectoryName(_socketPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
            // Set directory permissions to 0770 (owner/group only) for security
            TrySetUnixPermissions(dir,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute);
        }

        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
        _listener.Listen(5);

        // SECURITY: Set socket file permissions for container communication
        // The socket is protected by:
        // 1. Docker volume isolation - only containers with the volume mounted can access it
        // 2. File permissions - we use 0660 (owner/group only) for defense in depth
        // 3. Credential encryption - all credentials use ECDH + AES-GCM encryption
        // 4. Challenge expiration - credential challenges expire after 5 minutes
        //
        // For proper security, both containers should run as the same user (recommended)
        // or in the same group. Using 0660 instead of 0666 prevents access from
        // unrelated processes even if they somehow access the volume.
        TrySetUnixPermissions(_socketPath,
            UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite);

        _progress.OnLog(LogLevel.Info, $"Socket server listening on: {_socketPath}");

        // Start accepting connections
        _acceptTask = AcceptConnectionsAsync(_cts.Token);

        return Task.CompletedTask;
    }

    private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var clientSocket = await _listener!.AcceptAsync(cancellationToken);
                var clientId = Guid.NewGuid().ToString("N")[..8];
                var client = new ConnectedClient(clientId, clientSocket);

                _clients[clientId] = client;
                _progress.OnLog(LogLevel.Info, $"Client connected: {clientId}");
                OnClientConnected?.Invoke(clientId);

                // Handle client in background
                _ = HandleClientAsync(client, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Expected on shutdown
                break;
            }
            catch (Exception ex)
            {
                _progress.OnLog(LogLevel.Warning, $"Error accepting connection: {ex.Message}");
            }
        }
    }

    private async Task HandleClientAsync(ConnectedClient client, CancellationToken cancellationToken)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, client.CancellationToken);
        var token = linkedCts.Token;

        try
        {
            using var stream = new NetworkStream(client.Socket, ownsSocket: false);

            while (!token.IsCancellationRequested)
            {
                // Read length prefix (4 bytes, little-endian)
                var lengthBytes = new byte[4];
                var bytesRead = await ReadExactlyAsync(stream, lengthBytes, token);
                if (bytesRead == 0)
                {
                    // Client disconnected gracefully
                    break;
                }

                var length = BitConverter.ToInt32(lengthBytes, 0);
                if (length <= 0 || length > 10 * 1024 * 1024) // Max 10MB
                {
                    _progress.OnLog(LogLevel.Warning, $"Invalid message length from client {client.Id}: {length}");
                    break;
                }

                // Read message
                var messageBytes = new byte[length];
                bytesRead = await ReadExactlyAsync(stream, messageBytes, token);
                if (bytesRead == 0)
                {
                    break;
                }

                var json = Encoding.UTF8.GetString(messageBytes);
                _progress.OnLog(LogLevel.Debug, $"Received from {client.Id}: {json[..Math.Min(200, json.Length)]}...");

                // Parse and handle command
                CommandResponse response;
                try
                {
                    var request = JsonSerializer.Deserialize(json, DaemonSerializationContext.Default.CommandRequest);
                    if (request == null)
                    {
                        response = new CommandResponse
                        {
                            Id = "unknown",
                            Success = false,
                            Error = "Failed to parse command request"
                        };
                    }
                    else if (OnCommand == null)
                    {
                        response = new CommandResponse
                        {
                            Id = request.Id,
                            Success = false,
                            Error = "No command handler registered"
                        };
                    }
                    else
                    {
                        // Check authentication if shared secret is configured
                        if (!string.IsNullOrEmpty(_sharedSecret) && !client.IsAuthenticated)
                        {
                            // First command must be "auth" with correct secret
                            if (request.Type == "auth" && request.Parameters?.TryGetValue("secret", out var providedSecret) == true)
                            {
                                if (providedSecret == _sharedSecret)
                                {
                                    client.IsAuthenticated = true;
                                    _progress.OnLog(LogLevel.Info, $"Client {client.Id} authenticated successfully");
                                    response = new CommandResponse
                                    {
                                        Id = request.Id,
                                        Success = true,
                                        Message = "Authenticated"
                                    };
                                }
                                else
                                {
                                    _progress.OnLog(LogLevel.Warning, $"Client {client.Id} failed authentication - invalid secret");
                                    response = new CommandResponse
                                    {
                                        Id = request.Id,
                                        Success = false,
                                        Error = "Authentication failed: invalid secret"
                                    };
                                    // Disconnect on auth failure
                                    break;
                                }
                            }
                            else
                            {
                                _progress.OnLog(LogLevel.Warning, $"Client {client.Id} sent command without authenticating first");
                                response = new CommandResponse
                                {
                                    Id = request.Id,
                                    Success = false,
                                    Error = "Authentication required. Send 'auth' command with secret first."
                                };
                                // Disconnect unauthenticated client trying to send commands
                                break;
                            }
                        }
                        else
                        {
                            response = await OnCommand(request, token);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _progress.OnLog(LogLevel.Error, $"Error handling command: {ex.Message}");
                    response = new CommandResponse
                    {
                        Id = "error",
                        Success = false,
                        Error = ex.Message
                    };
                }

                // Send response
                await SendMessageAsync(client, response, DaemonSerializationContext.Default.CommandResponse, token);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown or client disconnect
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Client {client.Id} error: {ex.Message}");
        }
        finally
        {
            _clients.TryRemove(client.Id, out _);
            client.Dispose();
            _progress.OnLog(LogLevel.Info, $"Client disconnected: {client.Id}");
            OnClientDisconnected?.Invoke(client.Id);
        }
    }

    /// <summary>
    /// Send a credential challenge event to all connected clients.
    /// </summary>
    public async Task BroadcastCredentialChallengeAsync(SocketEvent<CredentialChallenge> eventData, CancellationToken cancellationToken = default)
    {
        var tasks = _clients.Values.Select(client =>
            SendEventToClientInternalAsync(client, eventData, DaemonSerializationContext.Default.SocketEventCredentialChallenge, cancellationToken));
        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Send a progress event to all connected clients.
    /// </summary>
    public async Task BroadcastProgressAsync(SocketEvent<PrefillProgressUpdate> eventData, CancellationToken cancellationToken = default)
    {
        var tasks = _clients.Values.Select(client =>
            SendEventToClientInternalAsync(client, eventData, DaemonSerializationContext.Default.SocketEventPrefillProgressUpdate, cancellationToken));
        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Send an auth state event to all connected clients.
    /// </summary>
    public async Task BroadcastAuthStateAsync(SocketEvent<AuthStateData> eventData, CancellationToken cancellationToken = default)
    {
        var tasks = _clients.Values.Select(client =>
            SendEventToClientInternalAsync(client, eventData, DaemonSerializationContext.Default.SocketEventAuthStateData, cancellationToken));
        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Send a credential challenge event to a specific client.
    /// </summary>
    public async Task SendCredentialChallengeAsync(string clientId, SocketEvent<CredentialChallenge> eventData, CancellationToken cancellationToken = default)
    {
        if (_clients.TryGetValue(clientId, out var client))
        {
            await SendEventToClientInternalAsync(client, eventData, DaemonSerializationContext.Default.SocketEventCredentialChallenge, cancellationToken);
        }
    }

    /// <summary>
    /// Send a progress event to a specific client.
    /// </summary>
    public async Task SendProgressAsync(string clientId, SocketEvent<PrefillProgressUpdate> eventData, CancellationToken cancellationToken = default)
    {
        if (_clients.TryGetValue(clientId, out var client))
        {
            await SendEventToClientInternalAsync(client, eventData, DaemonSerializationContext.Default.SocketEventPrefillProgressUpdate, cancellationToken);
        }
    }

    /// <summary>
    /// Send an auth state event to a specific client.
    /// </summary>
    public async Task SendAuthStateAsync(string clientId, SocketEvent<AuthStateData> eventData, CancellationToken cancellationToken = default)
    {
        if (_clients.TryGetValue(clientId, out var client))
        {
            await SendEventToClientInternalAsync(client, eventData, DaemonSerializationContext.Default.SocketEventAuthStateData, cancellationToken);
        }
    }

    private async Task SendEventToClientInternalAsync<T>(ConnectedClient client, T eventData, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        try
        {
            await client.SendLock.WaitAsync(cancellationToken);
            try
            {
                var json = JsonSerializer.Serialize(eventData, typeInfo);
                var bytes = Encoding.UTF8.GetBytes(json);

                using var stream = new NetworkStream(client.Socket, ownsSocket: false);
                await stream.WriteAsync(BitConverter.GetBytes(bytes.Length), cancellationToken);
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);

                _progress.OnLog(LogLevel.Debug, $"Sent event to {client.Id}");
            }
            finally
            {
                client.SendLock.Release();
            }
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Failed to send event to {client.Id}: {ex.Message}");
        }
    }

    private async Task SendMessageAsync<T>(ConnectedClient client, T message, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        await client.SendLock.WaitAsync(cancellationToken);
        try
        {
            var json = JsonSerializer.Serialize(message, typeInfo);
            var bytes = Encoding.UTF8.GetBytes(json);

            using var stream = new NetworkStream(client.Socket, ownsSocket: false);
            await stream.WriteAsync(BitConverter.GetBytes(bytes.Length), cancellationToken);
            await stream.WriteAsync(bytes, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            _progress.OnLog(LogLevel.Debug, $"Sent response to {client.Id}: {json[..Math.Min(200, json.Length)]}...");
        }
        finally
        {
            client.SendLock.Release();
        }
    }

    private static async Task<int> ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), cancellationToken);
            if (read == 0)
            {
                return 0; // Connection closed
            }
            totalRead += read;
        }
        return totalRead;
    }

    /// <summary>
    /// Stop the server and disconnect all clients.
    /// </summary>
    public async Task StopAsync()
    {
        _cts.Cancel();

        // Disconnect all clients
        foreach (var client in _clients.Values)
        {
            client.Dispose();
        }
        _clients.Clear();

        // Stop listener
        _listener?.Close();
        _listener?.Dispose();
        _listener = null;

        // Wait for accept task to complete
        if (_acceptTask != null)
        {
            try
            {
                await _acceptTask;
            }
            catch (OperationCanceledException)
            {
                // Expected
            }
        }

        // Remove socket file
        if (File.Exists(_socketPath))
        {
            try
            {
                File.Delete(_socketPath);
            }
            catch
            {
                // Ignore
            }
        }

        _progress.OnLog(LogLevel.Info, "Socket server stopped");
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        await StopAsync();
        _cts.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Attempts to set Unix file permissions. No-op on Windows.
    /// </summary>
    private void TrySetUnixPermissions(string path, UnixFileMode mode)
    {
        try
        {
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux) ||
                System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
            {
                File.SetUnixFileMode(path, mode);
                _progress.OnLog(LogLevel.Debug, $"Set permissions on {path}: {mode}");
            }
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Could not set permissions on {path}: {ex.Message}");
        }
    }

    private class ConnectedClient : IDisposable
    {
        public string Id { get; }
        public Socket Socket { get; }
        public SemaphoreSlim SendLock { get; } = new(1, 1);
        public CancellationTokenSource CancellationTokenSource { get; } = new();
        public CancellationToken CancellationToken => CancellationTokenSource.Token;

        /// <summary>
        /// Whether the client has been authenticated (only relevant when shared secret is configured).
        /// </summary>
        public bool IsAuthenticated { get; set; }

        public ConnectedClient(string id, Socket socket)
        {
            Id = id;
            Socket = socket;
        }

        public void Dispose()
        {
            CancellationTokenSource.Cancel();
            CancellationTokenSource.Dispose();
            SendLock.Dispose();
            try
            {
                Socket.Shutdown(SocketShutdown.Both);
            }
            catch
            {
                // Ignore
            }
            Socket.Dispose();
        }
    }
}

/// <summary>
/// Event message sent from server to client (unsolicited).
/// </summary>
public class SocketEvent<T>
{
    public string Type { get; init; } = string.Empty;
    public T? Data { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Credential challenge event sent when login requires credentials.
/// </summary>
public class CredentialChallengeEvent : SocketEvent<CredentialChallenge>
{
    public CredentialChallengeEvent(CredentialChallenge challenge)
    {
        Type = "credential-challenge";
        Data = challenge;
    }
}

/// <summary>
/// Progress event sent during prefill operations.
/// </summary>
public class ProgressEvent : SocketEvent<PrefillProgressUpdate>
{
    public ProgressEvent(PrefillProgressUpdate progress)
    {
        Type = "progress";
        Data = progress;
    }
}

/// <summary>
/// Auth state change event.
/// </summary>
public class AuthStateEvent : SocketEvent<AuthStateData>
{
    public AuthStateEvent(string state, string? message = null)
    {
        Type = "auth-state";
        Data = new AuthStateData { State = state, Message = message };
    }
}

public class AuthStateData
{
    public string State { get; init; } = string.Empty;
    public string? Message { get; init; }
}
