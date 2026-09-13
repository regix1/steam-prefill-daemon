using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using LancachePrefill.Common;
using Moq;
using Spectre.Console;
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
public sealed class ConcurrentPrefillTests
{
    [Fact]
    public async Task ThreeRuns_ReadBodiesTogetherAndCancelOnlyTheTarget()
    {
        var previousLimit = Environment.GetEnvironmentVariable("PREFILL_MAX_RUNS");
        Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", "3");
        var directory = Path.Combine(Path.GetTempPath(), "steam-runs-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        using var session = new Steam3Session(new TestConsole());
        typeof(Steam3Session).GetField("_isAuthenticated", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(session, true);
        var entered = Enumerable.Range(0, 3).Select(_ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously)).ToArray();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var disposed = new int[3];
        var sent = new int[3];
        var apps = new Dictionary<uint, AppInfo>();
        var manifests = new List<string>();
        using var api = new SteamPrefillApi(new StaticAuthProvider("test", "test"));
        using var commands = new SocketCommandInterface(0);
        try
        {
            for (uint index = 0; index < 3; index++)
            {
                var id = 2000 + index;
                var app = new AppInfo(session, id, new KeyValue { Children = { new KeyValue("common") { Children = { new KeyValue("type", "game"), new KeyValue("name", "Game " + id) } } } });
                var depot = new DepotInfo(new KeyValue(id.ToString()), id) { ManifestId = (ulong)Random.Shared.NextInt64(1, long.MaxValue) };
                app.Depots.Add(depot);
                apps.Add(id, app);
                session.LicenseManager._userLicenses.OwnedAppIds.Add(id);
                session.LicenseManager._userLicenses.OwnedDepotIds.Add(id);
                var manifest = (Manifest)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(Manifest));
                typeof(Manifest).GetProperty(nameof(Manifest.Files))!.SetValue(manifest, new List<FileData> { new(new DepotManifest.FileData { Chunks = new List<DepotManifest.ChunkData> { new() { ChunkID = new byte[20], CompressedLength = 3 } } }) });
                typeof(Manifest).GetProperty(nameof(Manifest.DepotId))!.SetValue(manifest, id);
                typeof(Manifest).GetProperty(nameof(Manifest.Id))!.SetValue(manifest, depot.ManifestId.Value);
                manifest.SaveToFile(depot.ManifestFileName);
                manifests.Add(depot.ManifestFileName);
            }
            var console = new ApiConsoleAdapter(new StaticAuthProvider("test", "test"), NullProgress.Instance);
            var sharedApp = new AppInfo(session, 3000, new KeyValue { Children = { new KeyValue("common") { Children = { new KeyValue("type", "game"), new KeyValue("name", "Shared game") } } } });
            sharedApp.Depots.Add(new DepotInfo(apps[2000].Depots[0]));
            apps.Add(3000, sharedApp);
            session.LicenseManager._userLicenses.OwnedAppIds.Add(3000);
            var catalog = new Mock<AppInfoHandler>(console, session, session.LicenseManager);
            catalog.Setup(handler => handler.RetrieveAppMetadataAsync(It.IsAny<List<uint>>(), It.IsAny<bool>(), It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
            catalog.Setup(handler => handler.GetAvailableGamesByIdAsync(It.IsAny<List<uint>>(), It.IsAny<CancellationToken>()))
                .Returns((List<uint> ids, CancellationToken _) => Task.FromResult(ids.Select(id => apps[id]).ToList()));
            catalog.Setup(handler => handler.GetAppInfoAsync(It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .Returns((uint id, CancellationToken _) => Task.FromResult(apps[id]));
            var servers = Enumerable.Range(0, 8).Select(index =>
            {
                var server = new Server();
                typeof(Server).GetProperty(nameof(Server.Host))!.SetValue(server, "cdn-" + index);
                return server;
            });
            var pool = new CdnPool(console, new ConcurrentStack<Server>(servers));
            var depotHandler = new DepotHandler(session, catalog.Object, new ManifestHandler(console, pool, session), Path.Combine(directory, "success.json"));
            var manager = new SteamManager(console, new DownloadArguments(), session, cdnPool: pool, appInfoHandler: catalog.Object,
                depotHandler: depotHandler, download: sink => new DownloadHandler(console, pool, new BodyHandler(entered, release, disposed, sent), "cache.invalid", sink));
            typeof(SteamPrefillApi).GetField("_steamManager", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(api, manager);
            typeof(SteamPrefillApi).GetField("_isInitialized", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(api, true);
            typeof(SocketCommandInterface).GetField("_api", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(commands, api);
            var status = Assert.IsType<StatusData>((await InvokeAsync(commands, new CommandRequest { Type = "status" })).Data);
            Assert.Equal(3, status.MaxConcurrentRuns);
            var ids = Enumerable.Range(0, 3).Select(_ => Guid.NewGuid().ToString("D")).ToArray();
            var starts = ids.Select((id, index) => new CommandRequest
            {
                Id = id,
                Type = "prefill",
                Parameters = new()
                {
                    ["protocolVersion"] = "2",
                    ["daemonInstanceId"] = status.DaemonInstanceId!,
                    ["appIds"] = "[" + (2000 + index) + "]",
                    ["force"] = "true",
                    ["maxConcurrency"] = "1"
                }
            }).ToArray();
            var owner = (OwnedOperationCoordinator)typeof(SocketCommandInterface).GetField("_prefillOperation", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(commands)!;
            Assert.True((await InvokeAsync(commands, starts[0])).Success);
            var changed = new CommandRequest { Id = ids[0], Type = "prefill", Parameters = new(starts[0].Parameters!) };
            changed.Parameters["force"] = "false";
            Assert.Equal("operation-conflict", (await InvokeAsync(commands, changed)).ErrorCode);
            var empty = new CommandRequest { Id = Guid.NewGuid().ToString("D"), Type = "prefill", Parameters = new(starts[0].Parameters!) };
            empty.Parameters["appIds"] = "[]";
            Assert.False((await InvokeAsync(commands, empty)).Success);
            await entered[0].Task.WaitAsync(TimeSpan.FromSeconds(5));
            foreach (var appId in new[] { 2000, 3000 })
            {
                var duplicate = new CommandRequest { Id = Guid.NewGuid().ToString("D"), Type = "prefill", Parameters = new(starts[0].Parameters!) };
                duplicate.Parameters["appIds"] = "[" + appId + "]";
                Assert.True((await InvokeAsync(commands, duplicate)).Success);
                await owner.WaitAsync(duplicate.Id).WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal("skippedOverlap", owner.GetOperation(duplicate.Id)!.Reason);
                Assert.Equal(1, sent[0]);
            }
            foreach (var start in starts.Skip(1)) Assert.True((await InvokeAsync(commands, start)).Success);
            await Task.WhenAll(entered.Select(signal => signal.Task)).WaitAsync(TimeSpan.FromSeconds(5));
            starts[1].Parameters!["appIds"] = "[999]";
            starts[1].Parameters!["force"] = "false";
            starts[1].Parameters!["maxConcurrency"] = "16";
            var excess = await InvokeAsync(commands, new CommandRequest { Id = Guid.NewGuid().ToString("D"), Type = "prefill", Parameters = new(starts[0].Parameters!) });
            Assert.Equal("run-limit", excess.ErrorCode);
            Assert.True((await InvokeAsync(commands, starts[0])).Success);
            var ambiguous = await InvokeAsync(commands, new CommandRequest { Type = "cancel-prefill" });
            Assert.Equal("ambiguous-operation", ambiguous.ErrorCode);
            var wrongInstance = await InvokeAsync(commands, new CommandRequest { Type = "cancel-prefill", Parameters = new() { ["operationId"] = ids[1], ["daemonInstanceId"] = "previous-instance" } });
            Assert.Equal("instance-changed", wrongInstance.ErrorCode);
            var unknown = await InvokeAsync(commands, new CommandRequest { Type = "cancel-prefill", Parameters = new() { ["operationId"] = "unknown", ["daemonInstanceId"] = status.DaemonInstanceId! } });
            Assert.Equal("operation-not-found", unknown.ErrorCode);
            var cancel = await InvokeAsync(commands, new CommandRequest { Type = "cancel-prefill", Parameters = new() { ["operationId"] = ids[0], ["daemonInstanceId"] = status.DaemonInstanceId! } });
            Assert.Equal("cancelling", Assert.IsType<RunSnapshot>(cancel.Data).State);
            await owner.WaitAsync(ids[0]).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(1, owner.GetOperation(ids[0])!.BytesTransferred);
            var repeated = await InvokeAsync(commands, new CommandRequest { Type = "cancel-prefill", Parameters = new() { ["operationId"] = ids[0], ["daemonInstanceId"] = status.DaemonInstanceId! } });
            Assert.Equal("cancelled", Assert.IsType<RunSnapshot>(repeated.Data).State);
            Assert.Equal(1, disposed[0]);
            Assert.Equal(0, disposed[1]);
            Assert.Equal(0, disposed[2]);
            release.TrySetResult();
            await Task.WhenAll(ids.Select(id => owner.WaitAsync(id))).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("cancelled", owner.GetOperation(ids[0])!.State);
            foreach (var id in ids.Skip(1))
            {
                var page = Assert.IsType<PrefillPage>((await InvokeAsync(commands, new CommandRequest { Type = "get-operation", Parameters = new() { ["operationId"] = id, ["daemonInstanceId"] = status.DaemonInstanceId! } })).Data);
                Assert.Equal("completed", page.Operation.State);
                Assert.Equal(3, page.Operation.BytesTransferred);
                Assert.True(page.Options.Force);
                Assert.Equal(1, page.Options.MaxConcurrency);
                Assert.Equal("success", Assert.Single(page.Items).Result);
                Assert.Single(page.Items[0].Depots!);
            }

            // Removing cached content must override this persistent daemon's successful history.
            var refill = new CommandRequest
            {
                Id = Guid.NewGuid().ToString("D"),
                Type = "prefill",
                Parameters = new(starts[2].Parameters!)
                {
                    ["force"] = "false",
                    ["cachedDepots"] = "[]"
                }
            };
            Assert.True((await InvokeAsync(commands, refill)).Success);
            await owner.WaitAsync(refill.Id).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(2, sent[2]);
            Assert.Equal(3, owner.GetOperation(refill.Id)!.BytesTransferred);
            Assert.Equal(1, owner.GetOperation(refill.Id)!.CompletedApps);

            var cached = new CommandRequest
            {
                Id = Guid.NewGuid().ToString("D"),
                Type = "prefill",
                Parameters = new(refill.Parameters!)
                {
                    ["cachedDepots"] = "[{\"depotId\":2002,\"manifestId\":\"" + apps[2002].Depots[0].ManifestId + "\"}]"
                }
            };
            Assert.True((await InvokeAsync(commands, cached)).Success);
            await owner.WaitAsync(cached.Id).WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(2, sent[2]);
            Assert.Equal(0, owner.GetOperation(cached.Id)!.BytesTransferred);
            Assert.Equal(1, owner.GetOperation(cached.Id)!.CachedApps);
        }
        finally
        {
            release.TrySetResult();
            await commands.StopAsync();
            Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", previousLimit);
            foreach (var path in manifests) File.Delete(path);
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task AccountQueueRetainsTimedOutJobAndKeepsPumpLive()
    {
        using var session = new Steam3Session(new TestConsole());
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = session.RequestAsync(() => { entered.TrySetResult(); return release.Task; });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        await Assert.ThrowsAsync<TimeoutException>(() => first.WaitAsync(TimeSpan.Zero));
        using var cancellation = new CancellationTokenSource();
        var cancelled = session.RequestAsync(() => Task.FromResult(-1), cancellation.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = session.RequestAsync(() => { secondEntered.TrySetResult(); return Task.FromResult(2); });
        Assert.False(secondEntered.Task.IsCompleted);
        var client = (SteamClient)typeof(Steam3Session).GetField("_steamClient", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(session)!;
        typeof(Steam3Session).GetField("_isAuthenticated", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(session, true);
        var callback = (SteamUser.LoggedOffCallback)System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(typeof(SteamUser.LoggedOffCallback));
        typeof(CallbackMsg).GetProperty(nameof(CallbackMsg.JobID))!.SetValue(callback, new JobID(0));
        var consumed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        session.AuthenticationLost += _ => consumed.TrySetResult();
        client.PostCallback(callback);
        await consumed.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.False(secondEntered.Task.IsCompleted);
        release.TrySetResult(1);
        Assert.Equal(1, await first);
        Assert.Equal(2, await second.WaitAsync(TimeSpan.FromSeconds(2)));
    }

    [Theory]
    [InlineData("preparing")]
    [InlineData("downloading")]
    [InlineData("cancelling")]
    [InlineData("completed")]
    [InlineData("failed")]
    [InlineData("cancelled")]
    public void EveryProgressStatePreservesRootIdentity(string state)
    {
        var snapshot = new RunSnapshot
        {
            OperationId = "run-1",
            DaemonInstanceId = "instance-1",
            Sequence = 7,
            StartedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
            State = state
        };
        var update = SocketCommandInterface.ToProgress(snapshot);
        using var document = System.Text.Json.JsonDocument.Parse(System.Text.Json.JsonSerializer.Serialize(update, DaemonSerializationContext.Default.PrefillProgressUpdate));
        Assert.Equal("run-1", document.RootElement.GetProperty("operationId").GetString());
        Assert.Equal("instance-1", document.RootElement.GetProperty("daemonInstanceId").GetString());
        Assert.Equal(7, document.RootElement.GetProperty("sequence").GetInt64());
        Assert.Equal(state, document.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task UndrainedRequestMakesSessionUnavailableUntilRestart()
    {
        using var session = new Steam3Session(new TestConsole(), requestTimeout: TimeSpan.FromMilliseconds(1));
        typeof(Steam3Session).GetField("_isAuthenticated", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(session, true);
        var response = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var request = session.RequestAsync(() => response.Task);
        await session.RequestsUnavailable.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(session.HasPendingRequests);
        Assert.False(session.IsAuthenticated);
        await Assert.ThrowsAsync<SteamPrefill.Models.Exceptions.SteamConnectionException>(() => session.RequestAsync(() => Task.FromResult(2)));
        response.TrySetResult(1);
        await Assert.ThrowsAsync<SteamPrefill.Models.Exceptions.SteamConnectionException>(() => request);
        await Assert.ThrowsAsync<SteamPrefill.Models.Exceptions.SteamConnectionException>(() => session.RequestAsync(() => Task.FromResult(3)));
    }

    internal static Task<CommandResponse> InvokeAsync(SocketCommandInterface commands, CommandRequest request) =>
        (Task<CommandResponse>)typeof(SocketCommandInterface).GetMethod("HandleCommandAsync", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(commands, new object[] { request, CancellationToken.None })!;

    private sealed class BodyHandler(TaskCompletionSource[] entered, TaskCompletionSource release, int[] disposed, int[] sent) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var index = int.Parse(request.RequestUri!.Segments[2].Trim('/')) - 2000;
            Interlocked.Increment(ref sent[index]);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new BodyStream(entered[index], release, disposed, index)) });
        }
    }

    private sealed class BodyStream(TaskCompletionSource entered, TaskCompletionSource release, int[] disposed, int index) : Stream
    {
        private int _read;
        private bool _disposed;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 3;
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_read++ == 0)
            {
                buffer.Span[0] = 0;
                return 1;
            }
            entered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
            if (_read > 2) return 0;
            buffer.Span[..2].Clear();
            return 2;
        }
        protected override void Dispose(bool disposing)
        {
            if (!_disposed) { _disposed = true; Interlocked.Increment(ref disposed[index]); }
            base.Dispose(disposing);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
