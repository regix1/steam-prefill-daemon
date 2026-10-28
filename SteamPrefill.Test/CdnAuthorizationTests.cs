using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Spectre.Console;
using Spectre.Console.Testing;
using SteamKit2;
using SteamKit2.CDN;
using SteamPrefill.Handlers;
using SteamPrefill.Handlers.Steam;
using SteamPrefill.Models;
using Xunit;

namespace SteamPrefill.Test;

[Collection("SteamAccountFile")]
public sealed class CdnAuthorizationTests
{
    [Fact]
    public async Task Manifest403_RequestsAuthorizationAndRetriesTheSameDomesticServer()
    {
        var console = new TestConsole();
        var calls = new List<(string Host, string Token)>();
        var authorizations = 0;
        var pool = new CdnPool(console, () => Task.FromResult(Array.Empty<Server>()), (app, depot, host) =>
        {
            Assert.Equal(1172470u, app);
            Assert.Equal(1172471u, depot);
            authorizations++;
            return Task.FromResult(("authkey=test-secret", DateTime.UtcNow.AddHours(1)));
        });
        var domestic = (Server)new DnsEndPoint("domestic.invalid", 80);
        pool.AvailableServerEndpoints.Push(domestic);
        var depot = new DepotInfo(new KeyValue("1172471"), 1172470) { ManifestId = (ulong)Random.Shared.NextInt64(1, long.MaxValue) };
        var manifest = (DepotManifest)RuntimeHelpers.GetUninitializedObject(typeof(DepotManifest));
        typeof(DepotManifest).GetProperty(nameof(DepotManifest.Files))!.SetValue(manifest, new List<DepotManifest.FileData>());
        var handler = new ManifestHandler(console, pool, _ => Task.FromResult(1UL), (_, _, server, token) =>
        {
            calls.Add((server.Host!, token));
            return token == "authkey=test-secret"
                ? Task.FromResult(manifest)
                : Task.FromException<DepotManifest>(new SteamKitWebRequestException("403", new HttpResponseMessage(HttpStatusCode.Forbidden)));
        });
        try
        {
            var (manifests, skipped) = await handler.GetAllManifestsAsync(new List<DepotInfo> { depot });
            Assert.Single(manifests);
            Assert.Empty(skipped);
            Assert.Equal(1, authorizations);
            Assert.Equal(new[] { ("domestic.invalid", (string)null!), ("domestic.invalid", "authkey=test-secret") }, calls);
            Assert.DoesNotContain("test-secret", console.Output, StringComparison.Ordinal);
        }
        finally { File.Delete(depot.ManifestFileName); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ChunkRequests_IncludeCachedAuthorizationAndPreserveForceFlag(bool force)
    {
        var console = new TestConsole();
        var authorizations = 0;
        var pool = new CdnPool(console, () => Task.FromResult(Array.Empty<Server>()), (_, _, _) =>
        {
            Interlocked.Increment(ref authorizations);
            return Task.FromResult(("authkey=test-secret&expires=123", DateTime.UtcNow.AddHours(1)));
        });
        pool.AvailableServerEndpoints.Push((Server)new DnsEndPoint("domestic.invalid", 80));
        var queries = new ConcurrentBag<string>();
        using var handler = new DownloadHandler(console, pool, new SignedContentHandler(queries), "cache.invalid");
        var failures = new ConcurrentBag<QueuedRequest>();
        await console.Progress().StartAsync(async ctx => failures = await handler.AttemptDownloadAsync(
            ctx, "Download", Enumerable.Repeat(default(QueuedRequest), 16).ToList(),
            new DownloadArguments { MaxConcurrentRequests = 16 }, forceRecache: force, appId: 1172470));
        Assert.Empty(failures);
        Assert.Equal(16, queries.Count);
        Assert.All(queries, query => Assert.Equal(force ? "?nocache=1&authkey=test-secret&expires=123" : "?authkey=test-secret&expires=123", query));
        Assert.Equal(1, authorizations);
        Assert.DoesNotContain("test-secret", console.Output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authorization_IsSharedAcrossConcurrentRequestsAndExpires()
    {
        var calls = 0;
        var clock = new ManualClock();
        var pool = new CdnPool(new TestConsole(), () => Task.FromResult(Array.Empty<Server>()), async (_, _, _) =>
        {
            await Task.Yield();
            var number = Interlocked.Increment(ref calls);
            return ("authkey=" + number, clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        }, clock);
        var server = (Server)new DnsEndPoint("domestic.invalid", 80);
        var tokens = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => pool.GetCdnAuthTokenAsync(1172470, 1172471, server)));
        Assert.All(tokens, token => Assert.Equal("authkey=1", token));
        Assert.Equal(1, calls);
        clock.Now = clock.Now.AddMinutes(11);
        Assert.Equal("authkey=2", await pool.GetCdnAuthTokenAsync(1172470, 1172471, server));
        Assert.Equal("authkey=3", await pool.GetCdnAuthTokenAsync(1172470, 3893181, server));
        Assert.Equal("authkey=4", await pool.GetCdnAuthTokenAsync(1172470, 1172471, (Server)new DnsEndPoint("other.invalid", 80)));
    }

    [Fact]
    public async Task CancellingOneAuthorizationWaiter_DoesNotCancelOtherDownloaders()
    {
        var pending = new TaskCompletionSource<(string, DateTime)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var pool = new CdnPool(new TestConsole(), () => Task.FromResult(Array.Empty<Server>()), (_, _, _) => { calls++; return pending.Task; });
        var server = (Server)new DnsEndPoint("domestic.invalid", 80);
        using var cancellation = new CancellationTokenSource();
        var cancelled = pool.GetCdnAuthTokenAsync(1172470, 1172471, server, cancellation.Token);
        var survivor = pool.GetCdnAuthTokenAsync(1172470, 1172471, server);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        pending.SetResult(("authkey=valid", DateTime.UtcNow.AddHours(1)));
        Assert.Equal("authkey=valid", await survivor);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Manifest403_RefreshesARefusedUnexpiredTokenOnce()
    {
        var console = new TestConsole();
        var calls = 0;
        var pool = new CdnPool(console, () => Task.FromResult(Array.Empty<Server>()), (_, _, _) =>
            Task.FromResult(("authkey=" + Interlocked.Increment(ref calls), DateTime.UtcNow.AddHours(1))));
        var server = (Server)new DnsEndPoint("domestic.invalid", 80);
        await pool.GetCdnAuthTokenAsync(1172470, 1172471, server);
        pool.AvailableServerEndpoints.Push(server);
        var depot = new DepotInfo(new KeyValue("1172471"), 1172470) { ManifestId = (ulong)Random.Shared.NextInt64(1, long.MaxValue) };
        var manifest = (DepotManifest)RuntimeHelpers.GetUninitializedObject(typeof(DepotManifest));
        typeof(DepotManifest).GetProperty(nameof(DepotManifest.Files))!.SetValue(manifest, new List<DepotManifest.FileData>());
        var usedTokens = new List<string>();
        var handler = new ManifestHandler(console, pool, _ => Task.FromResult(1UL), (_, _, _, token) =>
        {
            usedTokens.Add(token);
            return token == "authkey=2" ? Task.FromResult(manifest)
                : Task.FromException<DepotManifest>(new SteamKitWebRequestException("403", new HttpResponseMessage(HttpStatusCode.Forbidden)));
        });
        try
        {
            var (manifests, skipped) = await handler.GetAllManifestsAsync(new List<DepotInfo> { depot });
            Assert.Single(manifests);
            Assert.Empty(skipped);
            Assert.Equal(new[] { "authkey=1", "authkey=2" }, usedTokens);
            Assert.Equal(2, calls);
        }
        finally { File.Delete(depot.ManifestFileName); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConcurrentChunk403_RefreshesOnceBeforeRetrying(bool force)
    {
        var calls = 0;
        var arrivals = 0;
        var allRejected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var console = new TestConsole();
        var pool = new CdnPool(console, () => Task.FromResult(Array.Empty<Server>()), (_, _, _) =>
            Task.FromResult(("authkey=" + Interlocked.Increment(ref calls), DateTime.UtcNow.AddHours(1))));
        pool.AvailableServerEndpoints.Push((Server)new DnsEndPoint("domestic.invalid", 80));
        var queries = new ConcurrentBag<string>();
        using var handler = new DownloadHandler(console, pool, new CallbackHandler(async request =>
        {
            var query = request.RequestUri!.Query;
            queries.Add(query);
            if (query.Contains("authkey=1", StringComparison.Ordinal))
            {
                if (Interlocked.Increment(ref arrivals) == 16) allRejected.TrySetResult();
                await allRejected.Task.WaitAsync(TimeSpan.FromSeconds(5));
                return new HttpResponseMessage(HttpStatusCode.Forbidden);
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[] { 1 }) };
        }), "cache.invalid");
        var failures = new ConcurrentBag<QueuedRequest>();
        await console.Progress().StartAsync(async ctx => failures = await handler.AttemptDownloadAsync(
            ctx, "Download", Enumerable.Repeat(default(QueuedRequest), 16).ToList(),
            new DownloadArguments { MaxConcurrentRequests = 16 }, forceRecache: force, appId: 1172470));
        Assert.Empty(failures);
        Assert.Equal(2, calls);
        Assert.Equal(32, queries.Count);
        Assert.All(queries, query => Assert.Equal(force, query.Contains("nocache=1", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Chunk403_AfterReplacementStopsAfterOneRetryAndDropsTheEdge()
    {
        var calls = 0;
        var sends = 0;
        var console = new TestConsole();
        var pool = new CdnPool(console, () => Task.FromResult(Array.Empty<Server>()), (_, _, _) =>
            Task.FromResult(("authkey=" + Interlocked.Increment(ref calls), DateTime.UtcNow.AddHours(1))));
        foreach (var i in Enumerable.Range(0, 6))
            pool.AvailableServerEndpoints.Push((Server)new DnsEndPoint($"edge-{i}.invalid", 80));
        var selectedHost = pool.AvailableServerEndpoints.First().Host;
        using var handler = new DownloadHandler(console, pool, new CallbackHandler(_ =>
        {
            Interlocked.Increment(ref sends);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden));
        }), "cache.invalid");
        var failures = new ConcurrentBag<QueuedRequest>();
        await console.Progress().StartAsync(async ctx => failures = await handler.AttemptDownloadAsync(
            ctx, "Download", new List<QueuedRequest> { default },
            new DownloadArguments { MaxConcurrentRequests = 1 }, appId: 1172470));
        Assert.Single(failures);
        Assert.Equal(2, calls);
        Assert.Equal(2, sends);
        Assert.DoesNotContain(pool.AvailableServerEndpoints, server => server.Host == selectedHost);
    }

    private sealed class CallbackHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request);
    }

    private sealed class SignedContentHandler(ConcurrentBag<string> queries) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            queries.Add(request.RequestUri!.Query);
            return Task.FromResult(new HttpResponseMessage(request.RequestUri.Query.Contains("authkey=test-secret", StringComparison.Ordinal)
                ? HttpStatusCode.OK : HttpStatusCode.Forbidden) { Content = new ByteArrayContent(new byte[] { 1, 2, 3 }) });
        }
    }

    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
