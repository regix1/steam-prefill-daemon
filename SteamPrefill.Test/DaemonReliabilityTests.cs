using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using LancachePrefill.Common;
using Moq;
using Spectre.Console.Testing;
using SteamKit2;
using SteamKit2.CDN;
using SteamPrefill.Api;
using SteamPrefill.Handlers;
using SteamPrefill.Handlers.Steam;
using SteamPrefill.Models;
using SteamPrefill.Models.Exceptions;
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

    // A prefill's first Steam call is app metadata. When the connection is gone the PICS job never
    // completes, so the run used to sit silent with no download and no error until the caller's stall
    // timeout. The wait is bounded now, and the run fails with a reason naming Steam.
    [Fact(Timeout = 120_000)]
    public async Task AppMetadataRequest_TimesOutWhenSteamNeverAnswers()
    {
        var requestStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<SteamApps.PICSTokensCallback>(TaskCreationOptions.RunContinuationsAsynchronously);
        var steam3 = new Steam3Session(null);
        var appInfoHandler = new AppInfoHandler(
            new TestConsole(),
            steam3,
            steam3.LicenseManager,
            _ =>
            {
                requestStarted.TrySetResult();
                return response.Task;
            });

        var requestTask = appInfoHandler.GetAppInfoAsync(222, CancellationToken.None);
        await requestStarted.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var exception = await Assert.ThrowsAsync<SteamConnectionException>(() => requestTask);
        Assert.Contains("Steam did not answer", exception.Message, StringComparison.Ordinal);
        Assert.Contains("90 seconds", exception.Message, StringComparison.Ordinal);
        Assert.IsType<TimeoutException>(exception.InnerException);
        response.TrySetCanceled();
    }

    [Fact]
    public async Task ManifestRequestCodeFailure_RemovesOnlyBrokenDepot()
    {
        var attempts = 0;
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            _ =>
            {
                attempts++;
                return Task.FromResult(0UL);
            },
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var healthyDepot = CreateCachedDepot();
        var brokenDepot = CreateUncachedDepot();
        var depots = new List<DepotInfo> { healthyDepot, brokenDepot };

        var (manifests, skippedDepots) = await handler.GetAllManifestsAsync(depots);

        Assert.Single(manifests);
        Assert.Same(healthyDepot, Assert.Single(depots));
        Assert.Same(brokenDepot, Assert.Single(skippedDepots));
        Assert.Equal(3, attempts);

        File.Delete(healthyDepot.ManifestFileName);
    }

    [Fact]
    public async Task EveryManifestFailing_LeavesNoDepotsAndReportsEverySkip()
    {
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var depots = new List<DepotInfo> { CreateUncachedDepot(), CreateUncachedDepot() };

        var (manifests, skippedDepots) = await handler.GetAllManifestsAsync(depots);

        // This is the state the status path guards against, an app whose depot list emptied out while
        // fetching manifests has nothing left to compare and would otherwise read as up to date
        Assert.Empty(manifests);
        Assert.Empty(depots);
        Assert.Equal(2, skippedDepots.Count);
    }

    [Fact]
    public async Task ManifestFailureForOneDepot_KeepsTheAppFromReportingUpToDate()
    {
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var cachedDepot = CreateCachedDepot();
        var secondCachedDepot = CreateCachedDepot();
        var updatedDepot = CreateUncachedDepot();
        var depots = new List<DepotInfo> { cachedDepot, secondCachedDepot, updatedDepot };
        var depotHandler = new DepotHandler(console, new Steam3Session(null), null, null);
        depotHandler.SetCachedManifests(new[]
        {
            (cachedDepot.DepotId, cachedDepot.ManifestId!.Value),
            (secondCachedDepot.DepotId, secondCachedDepot.ManifestId!.Value)
        });

        var (_, skippedDepots) = await handler.GetAllManifestsAsync(depots);

        // Everything left in the list is cached, so the list on its own says the app is up to date.
        // The skipped depot is the only thing that keeps the app from being counted that way.
        Assert.True(depotHandler.AppIsUpToDate(depots));
        Assert.Same(updatedDepot, Assert.Single(skippedDepots));

        File.Delete(cachedDepot.ManifestFileName);
        File.Delete(secondCachedDepot.ManifestFileName);
    }

    [Fact]
    public async Task ManifestTransportFailure_SkipsOnlyTheBrokenDepot()
    {
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            _ => throw new SteamKitWebRequestException("404 Not Found", new HttpResponseMessage(HttpStatusCode.NotFound)),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var healthyDepot = CreateCachedDepot();
        var brokenDepot = CreateUncachedDepot();
        var depots = new List<DepotInfo> { healthyDepot, brokenDepot };

        var (manifests, skippedDepots) = await handler.GetAllManifestsAsync(depots);

        Assert.Single(manifests);
        Assert.Same(healthyDepot, Assert.Single(depots));
        Assert.Same(brokenDepot, Assert.Single(skippedDepots));

        File.Delete(healthyDepot.ManifestFileName);
    }

    [Fact]
    public async Task UnreadableCachedManifest_IsDeletedAndRequestedAgain()
    {
        var attempts = 0;
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            _ =>
            {
                attempts++;
                return Task.FromResult(0UL);
            },
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var depot = CreateUncachedDepot();
        File.WriteAllBytes(depot.ManifestFileName, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });
        var depots = new List<DepotInfo> { depot };

        var (manifests, skippedDepots) = await handler.GetAllManifestsAsync(depots);

        Assert.False(File.Exists(depot.ManifestFileName));
        Assert.Equal(3, attempts);
        Assert.Empty(manifests);
        Assert.Same(depot, Assert.Single(skippedDepots));
    }

    [Fact]
    public async Task VtolDlcDepot_RequestsManifestWithDlcAppId()
    {
        uint requestedAppId = 0;
        uint requestedDepotId = 0;
        var console = new TestConsole();
        var handler = new ManifestHandler(
            console,
            new CdnPool(console, new ConcurrentStack<Server>()),
            depot =>
            {
                requestedAppId = depot.ManifestRequestAppId;
                requestedDepotId = depot.DepotId;
                return Task.FromResult(0UL);
            },
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var depotKey = new KeyValue("1770480")
        {
            Children =
            {
                new KeyValue("dlcappid", "1770480"),
                new KeyValue("manifests")
                {
                    Children = { new KeyValue("public", "2836902461265788005") }
                }
            }
        };
        var depot = new DepotInfo(depotKey, 1770480);
        depot.AttachToParentApp(667970, 1770480);
        var depots = new List<DepotInfo> { depot };

        await handler.GetAllManifestsAsync(depots);

        Assert.Equal(1770480U, requestedAppId);
        Assert.Equal(1770480U, requestedDepotId);
        Assert.Equal(1770480U, depot.LicenseAppId);
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

        // The connection comes back from a continuation on the download task, so it is not returned on this thread
        var deadline = DateTime.UtcNow.AddSeconds(2);
        while (pool.AvailableServerEndpoints.IsEmpty && DateTime.UtcNow < deadline)
        {
            await Task.Delay(10);
        }
        Assert.Single(pool.AvailableServerEndpoints);
    }

    [Fact]
    public async Task AppStatus_WhenEveryManifestFails_IsNotReportedUpToDate()
    {
        var console = new TestConsole();
        var steam3 = new Steam3Session(null);
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(222);
        steam3.LicenseManager._userLicenses.OwnedDepotIds.Add(123);

        var appKeyValues = new KeyValue
        {
            Children =
            {
                new KeyValue("common")
                {
                    Children = { new KeyValue("type", "game") }
                }
            }
        };
        var app = new AppInfo(steam3, 222, appKeyValues);
        app.Depots.Add(new DepotInfo(new KeyValue("0"), 222)
        {
            DepotId = 123,
            ManifestId = unchecked((ulong)Random.Shared.NextInt64(1, long.MaxValue))
        });

        var appInfoHandler = new Mock<AppInfoHandler>(console, steam3, steam3.LicenseManager);
        appInfoHandler.Setup(e => e.RetrieveAppMetadataAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<bool>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.CompletedTask);
        appInfoHandler.Setup(e => e.GetAvailableGamesByIdAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(new List<AppInfo> { app }));
        appInfoHandler.Setup(e => e.GetAppInfoAsync(
                          It.IsAny<uint>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(app));

        // A pool holding the minimum server count keeps the status path from requesting CDNs from Steam
        var cdnPool = new CdnPool(console, new ConcurrentStack<Server>(Enumerable.Range(0, 5).Select(_ => new Server())));
        var manifestHandler = new ManifestHandler(
            console,
            cdnPool,
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var steamManager = new SteamManager(
            console,
            new DownloadArguments(),
            steam3,
            cdnPool: cdnPool,
            appInfoHandler: appInfoHandler.Object,
            depotHandler: new DepotHandler(steam3, appInfoHandler.Object, manifestHandler));

        var appStatuses = await steamManager.GetSelectedAppsStatusAsync(new List<uint> { 222 });

        var status = Assert.Single(appStatuses);
        Assert.False(status.IsUpToDate);
        Assert.Equal("No downloadable depots", status.UnavailableReason);
    }

    [Fact]
    public async Task AppStatus_WhenOneManifestFails_IsNotReportedUpToDate()
    {
        var console = new TestConsole();
        var steam3 = new Steam3Session(null);
        var cachedDepot = CreateCachedDepot();
        var brokenDepot = CreateUncachedDepot();
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(222);
        foreach (var depot in new[] { cachedDepot, brokenDepot })
        {
            steam3.LicenseManager._userLicenses.OwnedAppIds.Add(depot.LicenseAppId);
            steam3.LicenseManager._userLicenses.OwnedDepotIds.Add(depot.DepotId);
        }

        var appKeyValues = new KeyValue
        {
            Children =
            {
                new KeyValue("common")
                {
                    Children = { new KeyValue("type", "game") }
                }
            }
        };
        var app = new AppInfo(steam3, 222, appKeyValues);
        app.Depots.Add(cachedDepot);
        app.Depots.Add(brokenDepot);

        var appInfoHandler = new Mock<AppInfoHandler>(console, steam3, steam3.LicenseManager);
        appInfoHandler.Setup(e => e.RetrieveAppMetadataAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<bool>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.CompletedTask);
        appInfoHandler.Setup(e => e.GetAvailableGamesByIdAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(new List<AppInfo> { app }));
        appInfoHandler.Setup(e => e.GetAppInfoAsync(
                          It.IsAny<uint>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(app));

        var cdnPool = new CdnPool(console, new ConcurrentStack<Server>(Enumerable.Range(0, 5).Select(_ => new Server())));
        var manifestHandler = new ManifestHandler(
            console,
            cdnPool,
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var depotHandler = new DepotHandler(steam3, appInfoHandler.Object, manifestHandler);
        // The depot that keeps its manifest is already cached, so the depots left in the list say the app is up to date
        depotHandler.SetCachedManifests(new[] { (cachedDepot.DepotId, cachedDepot.ManifestId!.Value) });
        var steamManager = new SteamManager(
            console,
            new DownloadArguments(),
            steam3,
            cdnPool: cdnPool,
            appInfoHandler: appInfoHandler.Object,
            depotHandler: depotHandler);

        var appStatuses = await steamManager.GetSelectedAppsStatusAsync(new List<uint> { 222 });

        // One depot could not be fetched, so the app is incomplete and a prefill would have to run again
        var status = Assert.Single(appStatuses);
        Assert.False(status.IsUpToDate);

        File.Delete(cachedDepot.ManifestFileName);
    }

    [Fact]
    public async Task PrefillTwice_CountsOnlyTheSecondRun_AndNamesTheFailedApp()
    {
        // In daemon mode one manager serves every prefill command, and the summary used to be created
        // once with it. A second run therefore reported the first run's counts as well: a one-game
        // prefill could answer "4 updated, 13 failed", and the failure count climbed forever, so a
        // caller could not tell what THIS run did. The reason was invisible too, because the per-app
        // handler wrote it only to the console and the log file, never to the progress channel.
        var console = new TestConsole();
        var steam3 = new Steam3Session(null);
        var brokenDepot = CreateUncachedDepot();
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(222);
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(brokenDepot.LicenseAppId);
        steam3.LicenseManager._userLicenses.OwnedDepotIds.Add(brokenDepot.DepotId);

        var appKeyValues = new KeyValue
        {
            Children =
            {
                new KeyValue("common")
                {
                    Children = { new KeyValue("type", "game") }
                }
            }
        };
        var app = new AppInfo(steam3, 222, appKeyValues);
        app.Depots.Add(brokenDepot);

        var appInfoHandler = new Mock<AppInfoHandler>(console, steam3, steam3.LicenseManager);
        appInfoHandler.Setup(e => e.RetrieveAppMetadataAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<bool>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.CompletedTask);
        appInfoHandler.Setup(e => e.GetAvailableGamesByIdAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(new List<AppInfo> { app }));
        appInfoHandler.Setup(e => e.GetAppInfoAsync(
                          It.IsAny<uint>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(app));

        var cdnPool = new CdnPool(console, new ConcurrentStack<Server>(Enumerable.Range(0, 5).Select(_ => new Server())));
        var manifestHandler = new ManifestHandler(
            console,
            cdnPool,
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));

        var progress = new CallbackProgress();
        PrefillSummary? summary = null;
        progress.PrefillCompleted += completed => summary = completed;

        var steamManager = new SteamManager(
            console,
            new DownloadArguments(),
            steam3,
            progress,
            cdnPool: cdnPool,
            appInfoHandler: appInfoHandler.Object,
            depotHandler: new DepotHandler(steam3, appInfoHandler.Object, manifestHandler));

        await steamManager.DownloadMultipleAppsAsync(false, false, null, true);
        Assert.Equal(1, summary!.FailedApps);

        // The same manager, a second command. One app failed on this run, so the summary reports one,
        // not the two it has now seen in total.
        await steamManager.DownloadMultipleAppsAsync(false, false, null, true);
        Assert.Equal(1, summary!.FailedApps);
        Assert.Equal(1, summary.TotalApps);
    }

    [Fact]
    public async Task PrefillWhenEveryManifestFails_CountsTheAppAsFailed()
    {
        var console = new TestConsole();
        var steam3 = new Steam3Session(null);
        var brokenDepot = CreateUncachedDepot();
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(222);
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(brokenDepot.LicenseAppId);
        steam3.LicenseManager._userLicenses.OwnedDepotIds.Add(brokenDepot.DepotId);

        var appKeyValues = new KeyValue
        {
            Children =
            {
                new KeyValue("common")
                {
                    Children = { new KeyValue("type", "game") }
                }
            }
        };
        var app = new AppInfo(steam3, 222, appKeyValues);
        app.Depots.Add(brokenDepot);

        var appInfoHandler = new Mock<AppInfoHandler>(console, steam3, steam3.LicenseManager);
        appInfoHandler.Setup(e => e.RetrieveAppMetadataAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<bool>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.CompletedTask);
        appInfoHandler.Setup(e => e.GetAvailableGamesByIdAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(new List<AppInfo> { app }));
        appInfoHandler.Setup(e => e.GetAppInfoAsync(
                          It.IsAny<uint>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(app));

        var cdnPool = new CdnPool(console, new ConcurrentStack<Server>(Enumerable.Range(0, 5).Select(_ => new Server())));
        var manifestHandler = new ManifestHandler(
            console,
            cdnPool,
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));

        var progress = new CallbackProgress();
        AppDownloadResult? appResult = null;
        PrefillSummary? summary = null;
        progress.AppCompleted += (_, result) => appResult = result;
        progress.PrefillCompleted += completed => summary = completed;

        var steamManager = new SteamManager(
            console,
            new DownloadArguments(),
            steam3,
            progress,
            cdnPool: cdnPool,
            appInfoHandler: appInfoHandler.Object,
            depotHandler: new DepotHandler(steam3, appInfoHandler.Object, manifestHandler));

        await steamManager.DownloadMultipleAppsAsync(false, false, null, true);

        // The only depot was dropped while fetching manifests, which empties the list.  That empty list is a
        // manifest failure and not a filter that excluded everything, so the app has to be counted as failed
        Assert.Equal(AppDownloadResult.Failed, appResult);
        Assert.NotNull(summary);
        Assert.Equal(1, summary!.FailedApps);
    }

    [Fact]
    public async Task PrefillWhenOneManifestFails_CountsTheAppAsFailed()
    {
        var console = new TestConsole();
        var steam3 = new Steam3Session(null);
        var cachedDepot = CreateCachedDepot();
        var brokenDepot = CreateUncachedDepot();
        steam3.LicenseManager._userLicenses.OwnedAppIds.Add(222);
        foreach (var depot in new[] { cachedDepot, brokenDepot })
        {
            steam3.LicenseManager._userLicenses.OwnedAppIds.Add(depot.LicenseAppId);
            steam3.LicenseManager._userLicenses.OwnedDepotIds.Add(depot.DepotId);
        }

        var appKeyValues = new KeyValue
        {
            Children =
            {
                new KeyValue("common")
                {
                    Children = { new KeyValue("type", "game") }
                }
            }
        };
        var app = new AppInfo(steam3, 222, appKeyValues);
        app.Depots.Add(cachedDepot);
        app.Depots.Add(brokenDepot);

        var appInfoHandler = new Mock<AppInfoHandler>(console, steam3, steam3.LicenseManager);
        appInfoHandler.Setup(e => e.RetrieveAppMetadataAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<bool>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.CompletedTask);
        appInfoHandler.Setup(e => e.GetAvailableGamesByIdAsync(
                          It.IsAny<List<uint>>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(new List<AppInfo> { app }));
        appInfoHandler.Setup(e => e.GetAppInfoAsync(
                          It.IsAny<uint>(),
                          It.IsAny<CancellationToken>()))
                      .Returns(Task.FromResult(app));

        var cdnPool = new CdnPool(console, new ConcurrentStack<Server>(Enumerable.Range(0, 5).Select(_ => new Server())));
        var manifestHandler = new ManifestHandler(
            console,
            cdnPool,
            _ => Task.FromResult(0UL),
            (_, _, _) => throw new InvalidOperationException("Manifest download should not start without a request code."));
        var depotHandler = new DepotHandler(steam3, appInfoHandler.Object, manifestHandler);
        // The surviving depot is already cached, so the up to date check would claim the whole app is done
        depotHandler.SetCachedManifests(new[] { (cachedDepot.DepotId, cachedDepot.ManifestId!.Value) });

        var progress = new CallbackProgress();
        AppDownloadResult? appResult = null;
        PrefillSummary? summary = null;
        bool appStarted = false;
        progress.AppCompleted += (_, result) => appResult = result;
        progress.PrefillCompleted += completed => summary = completed;
        progress.AppStarted += _ => appStarted = true;

        var steamManager = new SteamManager(
            console,
            new DownloadArguments(),
            steam3,
            progress,
            cdnPool: cdnPool,
            appInfoHandler: appInfoHandler.Object,
            depotHandler: depotHandler);

        await steamManager.DownloadMultipleAppsAsync(false, false, null, true);

        // One depot of two could not be fetched, so the app is incomplete no matter how cached its siblings are
        Assert.True(appStarted);
        Assert.Equal(AppDownloadResult.Failed, appResult);
        Assert.NotNull(summary);
        Assert.Equal(1, summary!.FailedApps);
        Assert.Equal(0, summary.AlreadyUpToDate);
        Assert.Equal(0, summary.UpdatedApps);

        File.Delete(cachedDepot.ManifestFileName);
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

    private static DepotInfo CreateCachedDepot()
    {
        var depot = CreateUncachedDepot();
        // An empty manifest is all the cached path needs, these tests only care that the load succeeds
        File.WriteAllBytes(depot.ManifestFileName, Array.Empty<byte>());
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
