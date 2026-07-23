using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json;
using LancachePrefill.Common;
using Spectre.Console.Testing;
using SteamKit2;
using SteamKit2.CDN;
using SteamPrefill.Api;
using SteamPrefill.Handlers;
using SteamPrefill.Handlers.Steam;
using SteamPrefill.Models;
using Xunit;

namespace SteamPrefill.Test;

[Collection("SteamAccountFile")]
public sealed class DaemonReliabilityTests
{
    [Fact]
    public async Task ControlCommand_RespondsWhileSerializedCommandIsRunning()
    {
        var longCommandStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseLongCommand = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var port = GetFreeTcpPort();

        await using var server = new SocketServer(port, bindAddress: IPAddress.Loopback)
        {
            CommandLaneSelector = request => request.Type == "status"
                ? DaemonCommandLane.Control
                : DaemonCommandLane.Serialized,
            OnCommand = async (request, cancellationToken) =>
            {
                if (request.Type == "prefill")
                {
                    longCommandStarted.TrySetResult();
                    await releaseLongCommand.Task.WaitAsync(cancellationToken);
                }

                return new CommandResponse
                {
                    Id = request.Id,
                    Success = true,
                    Message = request.Type
                };
            }
        };

        await server.StartAsync();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        var stream = client.GetStream();
        await AuthenticateIfRequiredAsync(stream);

        await WriteRequestAsync(stream, new CommandRequest { Id = "long-1", Type = "prefill" });
        await longCommandStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await WriteRequestAsync(stream, new CommandRequest { Id = "control-1", Type = "status" });

        var controlResponse = await ReadResponseAsync(stream).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("control-1", controlResponse.Id);
        Assert.Equal("status", controlResponse.Message);

        releaseLongCommand.TrySetResult();
        var longResponse = await ReadResponseAsync(stream).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("long-1", longResponse.Id);
    }

    [Fact]
    public async Task ClientDisconnect_CancelsItsRunningCommand()
    {
        var commandStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var commandCancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var port = GetFreeTcpPort();

        await using var server = new SocketServer(port, bindAddress: IPAddress.Loopback)
        {
            CommandLaneSelector = _ => DaemonCommandLane.Concurrent,
            OnCommand = async (request, cancellationToken) =>
            {
                commandStarted.TrySetResult();
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
                finally
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        commandCancelled.TrySetResult();
                    }
                }

                return new CommandResponse { Id = request.Id, Success = true };
            }
        };

        await server.StartAsync();
        using (var client = new TcpClient())
        {
            await client.ConnectAsync(IPAddress.Loopback, port);
            var stream = client.GetStream();
            await AuthenticateIfRequiredAsync(stream);
            await WriteRequestAsync(stream, new CommandRequest { Id = "disconnect-1", Type = "prefill" });
            await commandStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        }

        await commandCancelled.Task.WaitAsync(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task PrefillCancellation_WaitsForCleanup_EmitsOneTerminalState_AndAllowsRestart()
    {
        var updates = new List<PrefillProgressUpdate>();
        var progress = new SocketCommandInterface.SocketProgress(updates.Add);
        await using var coordinator = new OwnedOperationCoordinator();
        var operationStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cleanupStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var allowCleanup = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        await coordinator.StartAsync(
            cancellationToken => SocketCommandInterface.RunPrefillOperationAsync(
                async (_, token) =>
                {
                    operationStarted.TrySetResult();
                    try
                    {
                        await Task.Delay(Timeout.InfiniteTimeSpan, token);
                    }
                    finally
                    {
                        cleanupStarted.TrySetResult();
                        await allowCleanup.Task;
                    }

                    return new PrefillResult { Success = true };
                },
                new PrefillOptions(),
                progress,
                cancellationToken),
            CancellationToken.None);

        await operationStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var cancelTask = coordinator.CancelAndWaitAsync();
        await cleanupStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(cancelTask.IsCompleted);

        allowCleanup.TrySetResult();
        var result = await cancelTask.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(OwnedOperationStatus.Cancelled, result.Status);
        Assert.Single(updates, update => update.State == "cancelled");
        Assert.DoesNotContain(updates, update => update.State is "completed" or "error");

        await coordinator.StartAsync(
            cancellationToken => SocketCommandInterface.RunPrefillOperationAsync(
                (_, _) => Task.FromResult(new PrefillResult { Success = true }),
                new PrefillOptions(),
                progress,
                cancellationToken),
            CancellationToken.None);

        var restartedResult = await coordinator.WaitAsync();
        Assert.Equal(OwnedOperationStatus.Completed, restartedResult.Status);
    }

    [Fact]
    public void SocketLogging_SuppressesDebugByDefault_AndPreservesWarnings()
    {
        var defaultLogs = new List<string>();
        var defaultProgress = new SocketCommandInterface.SocketProgress(logWriter: defaultLogs.Add);

        defaultProgress.OnLog(LogLevel.Debug, "hidden-debug");
        defaultProgress.OnLog(LogLevel.Warning, "visible-warning");

        Assert.DoesNotContain(defaultLogs, line => line.Contains("hidden-debug", StringComparison.Ordinal));
        Assert.Contains(defaultLogs, line => line.Contains("visible-warning", StringComparison.Ordinal));

        var debugLogs = new List<string>();
        var debugProgress = new SocketCommandInterface.SocketProgress(enableDebugLogs: true, logWriter: debugLogs.Add);
        debugProgress.OnLog(LogLevel.Debug, "visible-debug");

        Assert.Contains(debugLogs, line => line.Contains("visible-debug", StringComparison.Ordinal));
    }

    [Fact]
    public void DaemonStartupMessages_AreConcise()
    {
        var messages = new[]
        {
            DaemonMode.GetUnixStartupMessage("/tmp/daemon.sock"),
            DaemonMode.GetTcpStartupMessage(12345)
        };

        Assert.All(messages, message =>
        {
            Assert.DoesNotContain("┌", message, StringComparison.Ordinal);
            Assert.DoesNotContain("SECURITY", message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("[DEBUG]", message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void SteamKitListenerConstruction_DoesNotEnableGlobalDebugTracing()
    {
        var wasEnabled = DebugLog.Enabled;
        try
        {
            DebugLog.Enabled = false;
            _ = new SteamKitDebugListener(new TestConsole());
            Assert.False(DebugLog.Enabled);
        }
        finally
        {
            DebugLog.Enabled = wasEnabled;
        }
    }

    [Fact]
    public async Task SteamChartsRequest_PropagatesCallerCancellation()
    {
        var requestStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var httpClient = new HttpClient(new BlockingHttpHandler(requestStarted));
        using var cancellation = new CancellationTokenSource();

        var requestTask = SteamChartsService.MostPlayedByDailyPlayersAsync(
            new TestConsole(),
            httpClient,
            cancellation.Token);
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requestTask);
    }

    [Fact]
    public async Task CdnServerRequest_PropagatesCallerCancellation()
    {
        var requestStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<Server[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var pool = new CdnPool(
            new TestConsole(),
            () =>
            {
                requestStarted.TrySetResult();
                return response.Task;
            });
        using var cancellation = new CancellationTokenSource();

        var requestTask = pool.PopulateAvailableServersAsync(cancellation.Token);
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requestTask);
        response.TrySetCanceled();
    }

    [Fact]
    public async Task ManifestRequestCode_PropagatesCallerCancellation()
    {
        var requestStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<ulong>(TaskCreationOptions.RunContinuationsAsynchronously);
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            _ =>
            {
                requestStarted.TrySetResult();
                return response.Task;
            },
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start before the request code completes."));
        using var cancellation = new CancellationTokenSource();

        var requestTask = handler.GetAllManifestsAsync(
            new List<DepotInfo> { CreateUncachedDepot() },
            cancellation.Token);
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requestTask);
        response.TrySetCanceled();
    }

    [Fact]
    public async Task ManifestDownload_PropagatesCallerCancellation_AndDefersConnectionReuse()
    {
        var downloadStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<DepotManifest>(TaskCreationOptions.RunContinuationsAsynchronously);
        var console = new TestConsole();
        var server = new Server();
        var pool = new CdnPool(console, new ConcurrentStack<Server>(new[] { server }));
        var handler = new ManifestHandler(
            console,
            pool,
            _ => Task.FromResult(1UL),
            (_, _, _) =>
            {
                downloadStarted.TrySetResult();
                return response.Task;
            });
        using var cancellation = new CancellationTokenSource();

        var requestTask = handler.GetAllManifestsAsync(
            new List<DepotInfo> { CreateUncachedDepot() },
            cancellation.Token);
        await downloadStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requestTask);
        Assert.Empty(pool.AvailableServerEndpoints);

        response.TrySetCanceled();
        Assert.Single(pool.AvailableServerEndpoints);
    }

    [Fact]
    public async Task PerAppDownload_CallerCancellationIsNotCountedAsFailure()
    {
        var downloadStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var failureCount = 0;

        var downloadTask = SteamManager.DownloadAppsAsync(
            new[] { 1 },
            async (_, token) =>
            {
                downloadStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            },
            (_, _) => failureCount++,
            cancellation.Token);
        await downloadStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => downloadTask);
        Assert.Equal(0, failureCount);
    }

    private static int GetFreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static DepotInfo CreateUncachedDepot()
    {
        DepotInfo depot;
        do
        {
            var depotId = unchecked((uint)Random.Shared.NextInt64(1, uint.MaxValue));
            var manifestId = unchecked((ulong)Random.Shared.NextInt64(1, long.MaxValue));
            depot = new DepotInfo(new KeyValue("0"), depotId)
            {
                DepotId = depotId,
                ManifestId = manifestId
            };
        }
        while (File.Exists(depot.ManifestFileName));

        return depot;
    }

    private static async Task WriteRequestAsync(NetworkStream stream, CommandRequest request)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(request, DaemonSerializationContext.Default.CommandRequest);
        var prefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix);
        await stream.WriteAsync(payload);
    }

    private static async Task AuthenticateIfRequiredAsync(NetworkStream stream)
    {
        var secret = Environment.GetEnvironmentVariable("PREFILL_SOCKET_SECRET");
        if (string.IsNullOrEmpty(secret))
        {
            return;
        }

        await WriteRequestAsync(stream, new CommandRequest
        {
            Id = "auth-1",
            Type = "auth",
            Parameters = new Dictionary<string, string> { ["secret"] = secret }
        });
        var response = await ReadResponseAsync(stream).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(response.Success);
        Assert.Equal("auth-1", response.Id);
    }

    private static async Task<CommandResponse> ReadResponseAsync(NetworkStream stream)
    {
        var prefix = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(prefix);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload);
        return JsonSerializer.Deserialize(payload, DaemonSerializationContext.Default.CommandResponse)
            ?? throw new InvalidOperationException("The daemon returned an empty response.");
    }

    private sealed class BlockingHttpHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _requestStarted;

        public BlockingHttpHandler(TaskCompletionSource requestStarted)
        {
            _requestStarted = requestStarted;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            _requestStarted.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}
