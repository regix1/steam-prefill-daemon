using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text.Json;
using SteamPrefill.Api;
using Xunit;

namespace SteamPrefill.Test;

/// <summary>
/// With a socket secret set, a process that connects but never sends the secret must not receive pushed
/// events (sign-in state and progress).
/// </summary>
[Collection("SteamAccountFile")]
public sealed class UnauthenticatedClientEventTests
{
    private const string SocketSecretVariable = "PREFILL_SOCKET_SECRET";
    private const string Secret = "manager-secret";

    [Fact]
    public async Task ClientWithoutTheSecretNeverReceivesTheSignInState()
    {
        var originalSecret = Environment.GetEnvironmentVariable(SocketSecretVariable);
        Environment.SetEnvironmentVariable(SocketSecretVariable, Secret);
        var port = GetFreeTcpPort();
        await using var server = new SocketServer(port, bindAddress: IPAddress.Loopback)
        {
            OnCommand = (request, _) => Task.FromResult(new CommandResponse { Id = request.Id, Success = true })
        };

        try
        {
            await server.StartAsync();
            var clients = (System.Collections.IDictionary)typeof(SocketServer)
                .GetField("_clients", BindingFlags.Instance | BindingFlags.NonPublic)!
                .GetValue(server)!;

            using var bystander = new TcpClient();
            await bystander.ConnectAsync(IPAddress.Loopback, port);
            await WaitUntilAsync(() => clients.Count == 1);

            using var manager = new TcpClient();
            await manager.ConnectAsync(IPAddress.Loopback, port);
            var managerStream = manager.GetStream();
            await WriteRequestAsync(managerStream, new CommandRequest
            {
                Id = "auth-id",
                Type = "auth",
                Parameters = new Dictionary<string, string> { ["secret"] = Secret }
            });
            using (var authReply = await ReadFrameAsync(managerStream).WaitAsync(TimeSpan.FromSeconds(5)))
            {
                Assert.True(authReply.RootElement.GetProperty("success").GetBoolean());
            }

            await server.BroadcastAuthStateAsync(new AuthStateEvent("logged-in"));
            using (var managerEvent = await ReadFrameAsync(managerStream).WaitAsync(TimeSpan.FromSeconds(5)))
            {
                Assert.Equal("auth-state", managerEvent.RootElement.GetProperty("type").GetString());
            }

            // The bystander now sends a command without the secret. Its first frame must be the refusal of that
            // command; a sign-in event ahead of it means the event was pushed to a client that never authenticated.
            var bystanderStream = bystander.GetStream();
            await WriteRequestAsync(bystanderStream, new CommandRequest { Id = "status-id", Type = "status" });
            using var first = await ReadFrameAsync(bystanderStream).WaitAsync(TimeSpan.FromSeconds(5));
            var firstType = first.RootElement.TryGetProperty("type", out var type) ? type.GetString() : null;
            Assert.True(firstType != "auth-state",
                "A client that never sent the socket secret received the sign-in state event: " + first.RootElement.GetRawText());
            Assert.Equal("status-id", first.RootElement.GetProperty("id").GetString());
            Assert.False(first.RootElement.GetProperty("success").GetBoolean());
        }
        finally
        {
            await server.StopAsync();
            Environment.SetEnvironmentVariable(SocketSecretVariable, originalSecret);
        }
    }

    private static async Task WriteRequestAsync(NetworkStream stream, CommandRequest request)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(request, DaemonSerializationContext.Default.CommandRequest);
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix);
        await stream.WriteAsync(payload);
    }

    private static async Task<JsonDocument> ReadFrameAsync(NetworkStream stream)
    {
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix);
        var body = new byte[BinaryPrimitives.ReadInt32LittleEndian(prefix)];
        await stream.ReadExactlyAsync(body);
        return JsonDocument.Parse(body);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!condition())
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
