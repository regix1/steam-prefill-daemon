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
/// </summary>
public sealed class SocketServer : IAsyncDisposable
{
    private readonly string _socketPath;
    private readonly IPrefillProgress _progress;
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

        // Ensure directory exists
        var dir = Path.GetDirectoryName(_socketPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        _listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        _listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
        _listener.Listen(5);

        // Set socket file permissions to allow other containers to connect
        // This is necessary because Docker containers may run as different users
        try
        {
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux) ||
                System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
            {
                // Set permissions to 0666 (read/write for everyone)
                File.SetUnixFileMode(_socketPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                    UnixFileMode.OtherRead | UnixFileMode.OtherWrite);
                _progress.OnLog(LogLevel.Debug, $"Set socket permissions to 0666: {_socketPath}");
            }
        }
        catch (Exception ex)
        {
            _progress.OnLog(LogLevel.Warning, $"Could not set socket permissions: {ex.Message}");
        }

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
                        response = await OnCommand(request, token);
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
    /// Send an event to all connected clients.
    /// </summary>
    public async Task BroadcastEventAsync<T>(SocketEvent<T> eventData, CancellationToken cancellationToken = default)
    {
        var tasks = _clients.Values.Select(client =>
            SendEventToClientAsync(client, eventData, cancellationToken));

        await Task.WhenAll(tasks);
    }

    /// <summary>
    /// Send an event to a specific client.
    /// </summary>
    public async Task SendEventToClientAsync<T>(string clientId, SocketEvent<T> eventData, CancellationToken cancellationToken = default)
    {
        if (_clients.TryGetValue(clientId, out var client))
        {
            await SendEventToClientAsync(client, eventData, cancellationToken);
        }
    }

    private async Task SendEventToClientAsync<T>(ConnectedClient client, SocketEvent<T> eventData, CancellationToken cancellationToken)
    {
        try
        {
            await client.SendLock.WaitAsync(cancellationToken);
            try
            {
                var json = JsonSerializer.Serialize(eventData, SocketSerializationContext.Options);
                var bytes = Encoding.UTF8.GetBytes(json);

                using var stream = new NetworkStream(client.Socket, ownsSocket: false);
                await stream.WriteAsync(BitConverter.GetBytes(bytes.Length), cancellationToken);
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);

                _progress.OnLog(LogLevel.Debug, $"Sent event to {client.Id}: {eventData.Type}");
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

    private class ConnectedClient : IDisposable
    {
        public string Id { get; }
        public Socket Socket { get; }
        public SemaphoreSlim SendLock { get; } = new(1, 1);
        public CancellationTokenSource CancellationTokenSource { get; } = new();
        public CancellationToken CancellationToken => CancellationTokenSource.Token;

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

/// <summary>
/// Serialization context for socket events (using standard options, not source-generated for flexibility).
/// </summary>
internal static class SocketSerializationContext
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };
}
