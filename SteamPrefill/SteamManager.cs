namespace SteamPrefill
{
#nullable enable annotations

    public sealed class SteamManager : IDisposable
    {
        private readonly IAnsiConsole _ansiConsole;
        private readonly DownloadArguments _downloadArgs;

        private readonly Steam3Session _steam3;
        private readonly CdnPool _cdnPool;

        private readonly Func<IPrefillProgress, DownloadHandler> _download;
        private readonly SemaphoreSlim _preparation = new(1, 1);
        private readonly DepotHandler _depotHandler;
        private readonly AppInfoHandler _appInfoHandler;
        private readonly TimeProvider _clock;

        // Replaced at the start of every prefill rather than created once. In daemon mode one manager
        // serves many prefill commands, so a single instance accumulated across all of them: the
        // summary reported the container's whole lifetime, and its stopwatch measured from process
        // start. A one-game run could report "4 updated, 13 failed" and the failure count climbed by
        // one on every run forever, which made a caller unable to tell what THIS run did.
        private readonly AsyncLocal<PrefillSummaryResult> _summary = new();
        private PrefillSummaryResult _prefillSummaryResult { get => _summary.Value; set => _summary.Value = value; }
        private readonly CallbackProgress _progress;
        private readonly AsyncLocal<IPrefillProgress> _runProgress = new();

        public bool IsAuthenticated => _steam3.IsAuthenticated;
        internal string Username => _steam3.Username;
        internal DateTime? AuthExpiryUtc => _steam3.AuthExpiryUtc;
        internal bool HasPendingRequests => _steam3.HasPendingRequests;
        internal bool RestartRequired => _steam3.RequestsUnavailable.IsCompleted;
        public event Action<EResult?> AuthenticationLost
        {
            add => _steam3.AuthenticationLost += value;
            remove => _steam3.AuthenticationLost -= value;
        }

        public SteamManager(IAnsiConsole ansiConsole, DownloadArguments downloadArgs, ISteamAuthProvider? authProvider = null, IPrefillProgress? progress = null, Action<Action>? commitCredentials = null, TimeProvider? clock = null)
            : this(ansiConsole, downloadArgs, new Steam3Session(ansiConsole, authProvider, commitCredentials), progress, clock: clock)
        {
        }

        /// <summary>
        /// Takes the Steam session and the handlers built on top of it, so that a caller can supply handlers that
        /// don't need a connection to Steam.  Anything not supplied is built the same way the public constructor builds it.
        /// </summary>
        internal SteamManager(
            IAnsiConsole ansiConsole,
            DownloadArguments downloadArgs,
            Steam3Session steam3,
            IPrefillProgress progress = null,
            CdnPool cdnPool = null,
            AppInfoHandler appInfoHandler = null,
            DepotHandler depotHandler = null,
            Func<IPrefillProgress, DownloadHandler> download = null,
            TimeProvider? clock = null)
        {
            _ansiConsole = ansiConsole;
            _downloadArgs = downloadArgs;
            var output = progress ?? NullProgress.Instance;
            var callbacks = new CallbackProgress();
            callbacks.LogReceived += (level, message) => (_runProgress.Value ?? output).OnLog(level, message);
            callbacks.OperationStarted += name => (_runProgress.Value ?? output).OnOperationStarted(name);
            callbacks.OperationCompleted += (name, elapsed) => (_runProgress.Value ?? output).OnOperationCompleted(name, elapsed);
            callbacks.AppStarted += app => (_runProgress.Value ?? output).OnAppStarted(app);
            callbacks.DownloadProgressUpdated += value => (_runProgress.Value ?? output).OnDownloadProgress(value);
            callbacks.AppCompleted += (app, result) => (_runProgress.Value ?? output).OnAppCompleted(app, result);
            callbacks.PrefillCompleted += summary => (_runProgress.Value ?? output).OnPrefillCompleted(summary);
            callbacks.ErrorOccurred += (message, error) => (_runProgress.Value ?? output).OnError(message, error);
            _progress = callbacks;

            _steam3 = steam3;
            _cdnPool = cdnPool ?? new CdnPool(_ansiConsole, _steam3);
            _appInfoHandler = appInfoHandler ?? new AppInfoHandler(_ansiConsole, _steam3, _steam3.LicenseManager);
            _download = download ?? (sink => new DownloadHandler(_ansiConsole, _cdnPool, sink));
            _depotHandler = depotHandler ?? new DepotHandler(_ansiConsole, _steam3, _appInfoHandler, _cdnPool);
            _clock = clock ?? TimeProvider.System;
        }

        #region Startup + Shutdown

        /// <summary>
        /// Logs the user into the Steam network, and retrieves available CDN servers and account licenses.
        ///
        /// Required to be called first before using SteamManager class.
        /// </summary>
        public async Task InitializeAsync(CancellationToken cancellationToken = default)
        {
            var timer = Stopwatch.StartNew();
            _ansiConsole.LogMarkupLine("Starting login!");

            await _steam3.LoginToSteamAsync(cancellationToken);
            await _steam3.WaitForLicenseCallback(cancellationToken);

            _ansiConsole.LogMarkupLine("Steam session initialization complete!", timer);
            // White spacing + a horizontal rule to delineate that initialization has completed
            _ansiConsole.WriteLine();
            _ansiConsole.Write(new Rule());

        }

        public void Shutdown()
        {
            _steam3.Disconnect();
        }

        /// <summary>
        /// Updates download options that can change between prefill runs
        /// </summary>
        public void UpdateDownloadOptions(bool? force = null, List<OperatingSystem>? operatingSystems = null)
        {
            if (force.HasValue)
            {
                _downloadArgs.Force = force.Value;
            }
            if (operatingSystems != null && operatingSystems.Count > 0)
            {
                _downloadArgs.OperatingSystems = operatingSystems;
            }
        }

        public void Dispose()
        {
            _steam3.Dispose();
            _preparation.Dispose();
        }

        #endregion

        #region Prefill

        /// <summary>
        /// Given a list of AppIds, determines which apps require updates, and downloads the required depots.  By default,
        /// it will always include apps chosen by the select-apps command.
        /// </summary>
        /// <param name="downloadAllOwnedGames">If set to true, all games owned by the user will be downloaded</param>
        /// <param name="prefillRecentGames">If set to true, games played in the last 2 weeks will be downloaded</param>
        /// <param name="prefillPopularGames">If set to a value > 0, the most popular N games will be downloaded</param>
        /// <param name="prefillRecentlyPurchasedGames">If set to true, games purchased in the last 2 weeks will be downloaded</param>
        [SuppressMessage("Design", "CA1068", Justification = "Preserves existing positional cancellation callers.")]
        public async Task DownloadMultipleAppsAsync(bool downloadAllOwnedGames, bool prefillRecentGames,
                                                    int? prefillPopularGames, bool prefillRecentlyPurchasedGames,
                                                    CancellationToken cancellationToken = default, IPrefillProgress? progress = null,
                                                    IReadOnlyList<uint>? appIds = null, DownloadArguments? arguments = null)
        {
            _runProgress.Value = progress;
            var run = PrefillRun.Current.Value;
            var downloadArgs = arguments ?? run?.Arguments ?? new DownloadArguments
            {
                Force = _downloadArgs.Force,
                MaxConcurrentRequests = _downloadArgs.MaxConcurrentRequests,
                OperatingSystems = _downloadArgs.OperatingSystems.ToList(),
                Architecture = _downloadArgs.Architecture,
                Language = _downloadArgs.Language,
                TransferSpeedUnit = _downloadArgs.TransferSpeedUnit
            };
            using var downloadHandler = _download(progress ?? _progress);
            // Every Steam call below waits on a session that is already gone, so the run would otherwise
            // sit silent until the caller's stall timeout instead of reporting why nothing downloaded.
            if (!_steam3.IsAuthenticated)
            {
                throw new SteamConnectionException(SteamFailure.AuthLost);
            }

            // This run's counters and its own elapsed clock. Without this the summary carries every
            // earlier prefill in the same daemon process.
            _prefillSummaryResult = new PrefillSummaryResult();

            // Building out the list of AppIds to download
            // Only include previously selected apps if no specific filter is being used
            // When using filters like "recently purchased" or "recent games", users expect ONLY those games
            var hasSpecificFilter = downloadAllOwnedGames || prefillRecentGames || prefillPopularGames != null || prefillRecentlyPurchasedGames;
            await _preparation.WaitAsync(cancellationToken);
            List<uint> distinctAppIds;
            List<AppInfo> availableGames;
            try
            {
                var appIdsToDownload = appIds?.ToList() ?? (hasSpecificFilter ? new List<uint>() : LoadPreviouslySelectedApps());
                if (downloadAllOwnedGames)
                {
                    appIdsToDownload.AddRange(_steam3.LicenseManager.AllOwnedAppIds);
                }
                if (prefillRecentGames)
                {
                    var recentGames = await _appInfoHandler.GetRecentlyPlayedGamesAsync(cancellationToken);
                    appIdsToDownload.AddRange(recentGames.Select(e => (uint)e.appid));
                }
                if (prefillPopularGames != null)
                {
                    var popularGames = (await SteamChartsService.MostPlayedByDailyPlayersAsync(
                                           _ansiConsole,
                                           cancellationToken))
                                       .Take(prefillPopularGames.Value)
                                       .Select(e => e.AppId);
                    appIdsToDownload.AddRange(popularGames);
                }
                if (prefillRecentlyPurchasedGames)
                {
                    var recentApps = _steam3.LicenseManager.GetRecentlyPurchasedAppIds(30);
                    appIdsToDownload.AddRange(recentApps);

                    // Verbose logging for recently purchased games
                    await _appInfoHandler.RetrieveAppMetadataAsync(
                        recentApps,
                        cancellationToken: cancellationToken);
                    _ansiConsole.LogMarkupVerbose("[bold yellow]Recently purchased games (last 2 weeks):[/]");
                    foreach (var appId in recentApps)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var purchaseDate = _steam3.LicenseManager.GetPurchaseDateForApp(appId);
                        var appInfo = await _appInfoHandler.GetAppInfoAsync(appId, cancellationToken);
                        _ansiConsole.LogMarkupVerbose($"  {Green(appInfo.Name).PadRight(35)} - Purchased: {LightYellow(purchaseDate.ToLocalTime().ToString("yyyy-MM-dd"))}");
                    }
                }

                // AppIds can potentially be added twice when building out the full list of ids
                distinctAppIds = appIdsToDownload.Distinct().ToList();
                if (run != null && !run.Progress.Snapshot.SelectionResolved)
                    run.Progress.ResolveSelection(distinctAppIds.Select(id => id.ToString(System.Globalization.CultureInfo.InvariantCulture)));

                // Report progress for metadata retrieval (can be slow for large libraries)
                _progress.OnLog(LogLevel.Info, $"Loading metadata for {distinctAppIds.Count} apps...");
                await _appInfoHandler.RetrieveAppMetadataAsync(
                    distinctAppIds,
                    cancellationToken: cancellationToken);
                _progress.OnLog(LogLevel.Info, $"Metadata loaded for {distinctAppIds.Count} apps");

                // Whitespace divider
                _ansiConsole.WriteLine();

                availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(
                    distinctAppIds,
                    cancellationToken);
                if (run != null) availableGames = distinctAppIds.Join(availableGames, id => id, app => app.AppId, (_, app) => app).ToList();
                _progress.OnLog(LogLevel.Info, $"Starting prefill of {availableGames.Count} games");
            }
            finally { _preparation.Release(); }

            await DownloadAppsAsync(
                availableGames,
                async (app, token) =>
                {
                    try { await DownloadSingleAppAsync(app, downloadArgs, downloadHandler, token); }
                    finally { if (run != null) await run.ReleaseAsync(); }
                },
                (app, e) =>
                {
                    // Need to catch any exceptions that might happen during a single download, so that the other apps won't be affected
                    _ansiConsole.LogMarkupLine(Red($"Unexpected download error : {e.Message}  Skipping app..."));
                    _ansiConsole.MarkupLine("");
                    FileLogger.LogException(e);

                    // Also report it through the progress channel. The two lines above reach the
                    // console and app.log only, so a caller driving this over the daemon socket saw
                    // an app fail with no reason for it anywhere, and the run still summarised as a
                    // completion. Named app and exception type, because "Skipping app..." on its own
                    // does not say which app or why.
                    _progress.OnLog(
                        LogLevel.Error,
                        $"Prefill failed for {app}: {e.GetType().Name} - {e.Message}");

                    _prefillSummaryResult.FailedApps++;
                    _progress.OnAppCompleted(new AppDownloadInfo { AppId = app.AppId, Name = app.Name }, AppDownloadResult.Failed);
                },
                cancellationToken);
            await PrintUnownedAppsAsync(distinctAppIds, cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            _ansiConsole.LogMarkupLine("Prefill complete!");
            _prefillSummaryResult.RenderSummaryTable(_ansiConsole);

            // Notify completion via progress interface
            cancellationToken.ThrowIfCancellationRequested();
            _progress.OnPrefillCompleted(new PrefillSummary
            {
                TotalApps = _prefillSummaryResult.AlreadyUpToDate + _prefillSummaryResult.Updated + _prefillSummaryResult.FailedApps,
                UpdatedApps = _prefillSummaryResult.Updated,
                AlreadyUpToDate = _prefillSummaryResult.AlreadyUpToDate,
                FailedApps = _prefillSummaryResult.FailedApps,
                TotalBytesTransferred = (long)_prefillSummaryResult.TotalBytesTransferred.Bytes,
                TotalTime = _prefillSummaryResult.PrefillElapsedTime.Elapsed
            });
        }

        internal static async Task DownloadAppsAsync<TApp>(
            IEnumerable<TApp> apps,
            Func<TApp, CancellationToken, Task> downloadAppAsync,
            Action<TApp, Exception> onDownloadFailure,
            CancellationToken cancellationToken)
        {
            foreach (var app in apps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await downloadAppAsync(app, cancellationToken);
                }
                catch (SteamConnectionException)
                {
                    throw;
                }
                catch (Exception e) when (e is LancacheNotFoundException || e is InfiniteLoopException)
                {
                    throw;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception e)
                {
                    onDownloadFailure(app, e);
                }
            }
        }

        private async Task DownloadSingleAppAsync(AppInfo appInfo, DownloadArguments downloadArgs, DownloadHandler downloadHandler, CancellationToken cancellationToken = default)
        {
            var run = PrefillRun.Current.Value;
            if (run != null)
            {
                var claim = run.Claims.TryClaim(run.OperationId, new[] { "app:" + appInfo.AppId });
                if (claim == null)
                {
                    _progress.OnAppCompleted(new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, Reason = "skippedOverlap" }, AppDownloadResult.Skipped);
                    return;
                }
                run.Hold(claim);
            }
            await _preparation.WaitAsync(cancellationToken);
            List<DepotInfo> filteredDepots;
            List<QueuedRequest> chunkDownloadQueue = null;
            List<DepotInfo> skippedDepots = null;
            var linkedDepotsResolved = false;
            try
            {
                // Filter depots based on specified language/OS/cpu architecture/etc
                filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(
                    downloadArgs,
                    appInfo.Depots,
                    cancellationToken);
                if (filteredDepots.Empty())
                {
                    _ansiConsole.LogMarkupLine($"Starting {Cyan(appInfo)}  {LightYellow("No depots to download.  Current arguments filtered all depots")}");
                    _progress.OnAppCompleted(
                        new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, TotalBytes = 0 },
                        AppDownloadResult.NoDepotsToDownload);
                    return;
                }

                var requiredDepotCount = filteredDepots.Count;
                await _depotHandler.BuildLinkedDepotInfoAsync(filteredDepots, cancellationToken);
                linkedDepotsResolved = filteredDepots.Count == requiredDepotCount;
                if (filteredDepots.Empty())
                {
                    _ansiConsole.LogMarkupError($"Required linked depots for {Cyan(appInfo)} could not be resolved");
                    _prefillSummaryResult.FailedApps++;
                    _progress.OnAppCompleted(
                        new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, TotalBytes = 0 },
                        AppDownloadResult.Failed);
                    return;
                }

                // Get the full file list for each depot, and queue up the required chunks
                // We do this before the up-to-date check so we can report accurate sizes for cached games
                await _cdnPool.PopulateAvailableServersAsync(cancellationToken);

                if (run != null)
                {
                    var claim = run.Claims.TryClaim(run.OperationId, filteredDepots.Select(depot => "depot:" + depot.DepotId));
                    if (claim == null)
                    {
                        _progress.OnAppCompleted(new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, Reason = "skippedOverlap" }, AppDownloadResult.Skipped);
                        return;
                    }
                    run.Hold(claim);
                }
                await _ansiConsole.StatusSpinner().StartAsync(
                    "Fetching depot manifests...",
                    async _ =>
                    {
                        (chunkDownloadQueue, skippedDepots) = await _depotHandler.BuildChunkDownloadQueueAsync(
                            filteredDepots,
                            cancellationToken);
                    });
            }
            finally { _preparation.Release(); }
            if (skippedDepots.Any())
            {
                _ansiConsole.LogMarkupError(
                    $"{LightYellow(skippedDepots.Count)} depots for {Cyan(appInfo)} could not be downloaded");

                // Also report it through the progress channel. This path does not throw, so nothing
                // writes it to the log file either, and the console line above is the only record. A
                // caller driving the daemon over its socket therefore saw an app counted as failed
                // with no reason anywhere, which is the most common way a prefill "does nothing".
                _progress.OnLog(
                    LogLevel.Warning,
                    $"{skippedDepots.Count} of {filteredDepots.Count + skippedDepots.Count} depots for {appInfo.Name} "
                        + "could not be downloaded: their manifests could not be fetched.");
                // Every depot failed — nothing left to queue. That is a manifest failure, not a filter exclusion.
                if (filteredDepots.Empty())
                {
                    _prefillSummaryResult.FailedApps++;
                    _progress.OnAppCompleted(
                        new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, TotalBytes = 0 },
                        AppDownloadResult.Failed);
                    return;
                }
            }

            if (filteredDepots.Empty())
            {
                _ansiConsole.LogMarkupLine($"Starting {Cyan(appInfo)}  {LightYellow("No depots to download.  Current arguments filtered all depots")}");
                _progress.OnAppCompleted(
                    new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, TotalBytes = 0 },
                    AppDownloadResult.NoDepotsToDownload);
                return;
            }

            var totalBytes = ByteSize.FromBytes(chunkDownloadQueue.Sum(e => e.CompressedLength));

            // Build depot manifest info for cache tracking
            var depotManifests = filteredDepots
                .Where(d => d.ManifestId.HasValue)
                .Select(d => new DepotManifestInfo
                {
                    DepotId = d.DepotId,
                    ManifestId = d.ManifestId!.Value,
                    TotalBytes = chunkDownloadQueue.Where(request => request.DepotId == d.DepotId).Sum(request => request.CompressedLength)
                })
                .ToList();

            // We will want to re-download the entire app, if any of the depots have been updated
            if (downloadArgs.Force == false && linkedDepotsResolved && !skippedDepots.Any() &&
                _depotHandler.AppIsUpToDate(filteredDepots, run?.CacheSnapshot == true ? run.Options.CachedDepots : null))
            {
                _prefillSummaryResult.AlreadyUpToDate++;
                var cachedAppInfo = new AppDownloadInfo
                {
                    AppId = appInfo.AppId,
                    Name = appInfo.Name,
                    TotalBytes = (long)totalBytes.Bytes,
                    Depots = depotManifests
                };
                // Notify app started so frontend can animate the cached game
                _progress.OnAppStarted(cachedAppInfo);
                _progress.OnAppCompleted(cachedAppInfo, AppDownloadResult.AlreadyUpToDate);
                return;
            }

            _ansiConsole.LogMarkupLine($"Starting {Cyan(appInfo)}");

            // Finally run the queued downloads
            var downloadTimer = Stopwatch.StartNew();

            // Notify that app download is starting
            var appDownloadInfo = new AppDownloadInfo
            {
                AppId = appInfo.AppId,
                Name = appInfo.Name,
                TotalBytes = (long)totalBytes.Bytes,
                Depots = depotManifests
            };
            _progress.OnAppStarted(appDownloadInfo);

            _ansiConsole.LogMarkupVerbose($"Downloading {Magenta(totalBytes.ToDecimalString())} from {LightYellow(chunkDownloadQueue.Count)} chunks");

            if (AppConfig.SkipDownloads)
            {
                _ansiConsole.MarkupLine("");
                _progress.OnAppCompleted(appDownloadInfo, AppDownloadResult.Skipped);
                return;
            }

            var downloadSuccessful = await downloadHandler.DownloadQueuedChunksAsync(chunkDownloadQueue, downloadArgs,
                appId: appInfo.AppId, appName: appInfo.Name, cancellationToken: cancellationToken);
            _prefillSummaryResult.TotalBytesTransferred += run == null ? totalBytes : ByteSize.FromBytes(run.Bytes(appInfo.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            if (downloadSuccessful)
            {
                if (!linkedDepotsResolved || skippedDepots.Any())
                {
                    // Sibling depots were cached, but the app is still incomplete.
                    _prefillSummaryResult.FailedApps++;
                    _progress.OnAppCompleted(appDownloadInfo, AppDownloadResult.Failed);
                }
                else
                {
                    var item = run == null ? null : new RunItemSnapshot
                    {
                        AppId = appInfo.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        Name = appInfo.Name,
                        State = "completed",
                        Result = "success",
                        TotalBytes = appDownloadInfo.TotalBytes,
                        BytesTransferred = run.Bytes(appInfo.AppId.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    };
                    var committed = false;
                    _steam3.WhileAuthenticated(() => committed = _depotHandler.MarkDownloadAsSuccessful(filteredDepots, run?.Progress, item), cancellationToken);
                    if (!committed) return;
                    _prefillSummaryResult.Updated++;
                    if (run == null) _progress.OnAppCompleted(appDownloadInfo, AppDownloadResult.Success);

                    // Logging some metrics about the download
                    _ansiConsole.LogMarkupLine($"Finished in {LightYellow(downloadTimer.FormatElapsedString())} - {Magenta(totalBytes.CalculateBitrate(downloadTimer))}");
                    _ansiConsole.WriteLine();
                }
            }
            else
            {
                _prefillSummaryResult.FailedApps++;
                _progress.OnAppCompleted(appDownloadInfo, AppDownloadResult.Failed);
            }
            downloadTimer.Stop();
        }

        #endregion

        #region Select Apps

        public void SetAppsAsSelected(List<TuiAppInfo> tuiAppModels)
        {
            List<uint> selectedAppIds = tuiAppModels.Where(e => e.IsSelected)
                                                    .Select(e => UInt32.Parse(e.AppId))
                                                    .ToList();
            File.WriteAllText(AppConfig.UserSelectedAppsPath, JsonSerializer.Serialize(selectedAppIds, SerializationContext.Default.ListUInt32));

            _ansiConsole.LogMarkupLine($"Selected {Magenta(selectedAppIds.Count)} apps to prefill!  ");
        }

        public List<uint> LoadPreviouslySelectedApps()
        {
            if (!File.Exists(AppConfig.UserSelectedAppsPath))
            {
                return new List<uint>();
            }

            return JsonSerializer.Deserialize(File.ReadAllText(AppConfig.UserSelectedAppsPath), SerializationContext.Default.ListUInt32);
        }

        /// <summary>
        /// Populates the internal cache with externally provided cached depot manifest data.
        /// This allows the daemon to know which games are already cached without having downloaded them in this session.
        /// Used by lancache-manager to restore cache state after daemon restart.
        /// </summary>
        /// <param name="cachedDepots">List of cached depot info with depot ID and manifest ID</param>
        public void SetCachedManifests(IEnumerable<(uint DepotId, ulong ManifestId)> cachedDepots)
        {
            _depotHandler.SetCachedManifests(cachedDepots);
        }

        /// <summary>
        /// Clears all cached manifests from the internal cache.
        /// This forces all games to be re-evaluated on the next prefill.
        /// Used by lancache-manager when clearing the prefill cache database.
        /// </summary>
        /// <returns>The number of depots that were cleared</returns>
        public int ClearCachedManifests()
        {
            return _depotHandler.ClearCachedManifests();
        }


        /// <summary>
        /// Gets status information for selected apps including download sizes.
        /// </summary>
        public async Task<List<AppStatus>> GetSelectedAppsStatusAsync(
            List<uint> appIds,
            List<CachedDepotInput>? cachedDepots = null,
            CancellationToken cancellationToken = default)
        {
            await _preparation.WaitAsync(cancellationToken);
            try
            {
                // Force-refresh app metadata for these specific apps to ensure accurate size calculations
                _appInfoHandler.InvalidateApps(appIds);
                await _appInfoHandler.RetrieveAppMetadataAsync(
                    appIds,
                    cancellationToken: cancellationToken);
                await _cdnPool.PopulateAvailableServersAsync(cancellationToken);

                var appStatuses = new ConcurrentBag<AppStatus>();
                var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(appIds, cancellationToken);

                _ansiConsole.LogMarkupVerbose($"Getting status for {Magenta(availableGames.Count)} available games out of {Magenta(appIds.Count)} requested");

                // Build OS names string for error messages
                var selectedOsNames = string.Join(", ", _downloadArgs.OperatingSystems.Select(os => os.Name));

                Dictionary<uint, List<CachedDepotInput>>? cachedByApp = null;
                IReadOnlyCollection<string>? cachedManifests = null;
                if (cachedDepots != null)
                {
                    cachedByApp = cachedDepots
                        .GroupBy(depot => depot.AppId)
                        .ToDictionary(group => group.Key, group => group.ToList());
                    cachedManifests = cachedByApp.Values
                        .SelectMany(depots => depots)
                        .Select(depot => $"{depot.DepotId}:{depot.ManifestId}")
                        .ToHashSet(StringComparer.Ordinal);
                    _ansiConsole.LogMarkupVerbose($"Using {cachedDepots.Count} cached depot manifests from {cachedByApp.Count} app records for isUpToDate calculation");
                }

                await Parallel.ForEachAsync(
                    availableGames,
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = 5,
                        CancellationToken = cancellationToken
                    },
                    async (app, loopToken) =>
                {
                    try
                    {
                        _ansiConsole.LogMarkupVerbose($"Processing {Cyan(app.Name)}: {app.Depots.Count} depots");
                        var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(
                            _downloadArgs,
                            app.Depots,
                            loopToken);
                        _ansiConsole.LogMarkupVerbose($"  Filtered to {filteredDepots.Count} depots");

                        // Check if game has no depots for the selected OS
                        if (filteredDepots.Count == 0 && app.Depots.Count > 0)
                        {
                            // Game has depots but none match the selected OS
                            appStatuses.Add(new AppStatus
                            {
                                AppId = app.AppId,
                                Name = app.Name,
                                DownloadSize = 0,
                                IsUpToDate = false,
                                IsUnsupportedOs = true,
                                UnavailableReason = $"Not available for {selectedOsNames}"
                            });
                            return;
                        }

                        var requiredDepotCount = filteredDepots.Count;
                        await _depotHandler.BuildLinkedDepotInfoAsync(filteredDepots, loopToken);
                        var linkedDepotsResolved = filteredDepots.Count == requiredDepotCount;
                        if (filteredDepots.Count == 0)
                        {
                            appStatuses.Add(new AppStatus
                            {
                                AppId = app.AppId,
                                Name = app.Name,
                                DownloadSize = 0,
                                IsUpToDate = false,
                                UnavailableReason = "No downloadable depots"
                            });
                            return;
                        }

                        var (allChunksForApp, skippedDepots) = await _depotHandler.BuildChunkDownloadQueueAsync(
                            filteredDepots,
                            loopToken);
                        // Every depot can be dropped while fetching manifests, and an empty list would otherwise
                        // report the app as up to date with nothing left to download
                        if (filteredDepots.Count == 0)
                        {
                            appStatuses.Add(new AppStatus
                            {
                                AppId = app.AppId,
                                Name = app.Name,
                                DownloadSize = 0,
                                IsUpToDate = false,
                                UnavailableReason = "No downloadable depots"
                            });
                            return;
                        }

                        var downloadSize = allChunksForApp.Sum(e => e.CompressedLength);

                        var isUpToDate = _downloadArgs.Force == false && linkedDepotsResolved
                            && _depotHandler.AppIsUpToDate(filteredDepots, cachedManifests);

                        // A depot that couldn't be fetched is removed from the list, so the depots left behind can all be
                        // cached and still leave the app incomplete.  A prefill counts this app as failed, so the status
                        // has to report it as needing a download instead of up to date.
                        if (skippedDepots.Any())
                        {
                            isUpToDate = false;
                        }

                        appStatuses.Add(new AppStatus
                        {
                            AppId = app.AppId,
                            Name = app.Name,
                            DownloadSize = downloadSize,
                            IsUpToDate = isUpToDate
                        });
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (SteamConnectionException ex) when (ex.Failure != null)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        // Log the error so we can debug size calculation failures
                        _ansiConsole.LogMarkupError($"Failed to get size for {app.Name} ({app.AppId}): {ex.Message}");
                        FileLogger.LogException($"Failed to get app status for {app.Name}", ex);

                        // If we can't get info for an app, add it with zero size
                        appStatuses.Add(new AppStatus
                        {
                            AppId = app.AppId,
                            Name = app.Name,
                            DownloadSize = 0,
                            IsUpToDate = false,
                            UnavailableReason = "Failed to calculate size"
                        });
                    }
                });

                return appStatuses.OrderBy(a => a.Name).ToList();
            }
            finally { _preparation.Release(); }
        }


        /// <summary>
        /// Checks cache status by comparing cached depot manifests against Steam's current manifests.
        /// This allows accurate detection of which apps are truly up-to-date even when daemon restarts.
        /// </summary>
        [SuppressMessage("Design", "CA1068", Justification = "Preserves existing positional cancellation callers.")]
        public async Task<CacheStatusResult> CheckCacheStatusAsync(
            List<CachedDepotInput> cachedDepots,
            CancellationToken cancellationToken = default,
            List<uint>? appIds = null,
            List<CacheAppScope>? scope = null,
            DateTimeOffset? expiresAtUtc = null,
            int? version = null)
        {
            var requestedAppIds = (appIds ?? cachedDepots.Select(depot => depot.AppId)).Distinct().ToList();
            var versionTwo = version == 2;
            var statuses = new ConcurrentDictionary<uint, AppCacheStatus>();
            var deadlineReached = false;

            AppCacheStatus Unknown(uint appId, string name, CacheReason reason) => new()
            {
                AppId = appId,
                Name = name,
                IsUpToDate = false,
                Outcome = CacheOutcome.Unknown,
                Reason = reason,
                DownloadSize = 0,
                OutdatedDepots = new List<OutdatedDepot>()
            };

            CacheStatusResult BuildResult()
            {
                if (versionTwo)
                {
                    foreach (var appId in requestedAppIds)
                    {
                        statuses.TryAdd(appId, Unknown(
                            appId,
                            "",
                            deadlineReached ? CacheReason.DeadlineReached : CacheReason.InvalidResult));
                    }

                    var ordered = requestedAppIds.Select(appId => statuses[appId]).ToList();
                    return new CacheStatusResult
                    {
                        Version = 2,
                        Apps = ordered,
                        Message = null
                    };
                }

                var legacy = statuses.Values
                    .Where(status => status.Outcome != CacheOutcome.Unknown)
                    .OrderBy(status => status.Name)
                    .Select(status => new AppCacheStatus
                    {
                        AppId = status.AppId,
                        Name = status.Name,
                        IsUpToDate = status.IsUpToDate,
                        DownloadSize = status.DownloadSize,
                        OutdatedDepots = status.OutdatedDepots
                    })
                    .ToList();
                var upToDate = legacy.Count(status => status.IsUpToDate);
                var needsUpdate = legacy.Count - upToDate;
                var totalDownloadSize = ByteSize.FromBytes(legacy.Sum(status => status.DownloadSize));
                return new CacheStatusResult
                {
                    Apps = legacy,
                    Message = $"{upToDate} apps up-to-date, {needsUpdate} need updates ({totalDownloadSize.ToDecimalString()} to download)"
                };
            }

            if (requestedAppIds.Count == 0)
            {
                return versionTwo
                    ? BuildResult()
                    : new CacheStatusResult
                    {
                        Apps = new List<AppCacheStatus>(),
                        Message = "No cached depots provided"
                    };
            }

            TimeSpan? reserveDelay = null;
            if (expiresAtUtc.HasValue)
            {
                reserveDelay = expiresAtUtc.Value - _clock.GetUtcNow() - TimeSpan.FromSeconds(2);
                if (reserveDelay <= TimeSpan.Zero)
                {
                    deadlineReached = true;
                    return BuildResult();
                }
            }

            using var reserveCancellation = reserveDelay.HasValue
                ? new CancellationTokenSource(reserveDelay.Value, _clock)
                : null;
            using var inspectionCancellation = reserveCancellation != null
                ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, reserveCancellation.Token)
                : null;
            var inspectionToken = inspectionCancellation?.Token ?? cancellationToken;
            var preparationHeld = false;
            try
            {
                await _preparation.WaitAsync(inspectionToken);
                preparationHeld = true;
                inspectionToken.ThrowIfCancellationRequested();

                var cachedManifests = cachedDepots
                    .Select(depot => $"{depot.DepotId}:{depot.ManifestId}")
                    .ToHashSet(StringComparer.Ordinal);
                var cachedByDepot = cachedDepots
                    .GroupBy(depot => depot.DepotId)
                    .ToDictionary(group => group.Key,
                        group => group.Select(depot => depot.ManifestId).Distinct().ToArray());

                // Force-refresh app metadata for these specific apps to ensure accurate manifest info
                _appInfoHandler.InvalidateApps(requestedAppIds);
                await _appInfoHandler.RetrieveAppMetadataAsync(
                    requestedAppIds,
                    cancellationToken: inspectionToken);
                if (!versionTwo)
                    await _cdnPool.PopulateAvailableServersAsync(inspectionToken);

                var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(requestedAppIds, inspectionToken);
                var gamesById = availableGames
                    .GroupBy(app => app.AppId)
                    .ToDictionary(group => group.Key, group => group.First());
                var authorityByApp = versionTwo
                    ? scope!.ToDictionary(item => item.AppId, item => item.Authority!.Value)
                    : null;

                _ansiConsole.LogMarkupVerbose($"Checking cache status for {Magenta(availableGames.Count)} available games out of {Magenta(requestedAppIds.Count)} requested");

                await Parallel.ForEachAsync(
                    requestedAppIds,
                    new ParallelOptions
                    {
                        MaxDegreeOfParallelism = 5,
                        CancellationToken = inspectionToken
                    },
                    async (app, loopToken) =>
                {
                    loopToken.ThrowIfCancellationRequested();
                    if (!gamesById.TryGetValue(app, out var game))
                    {
                        if (versionTwo)
                            statuses.TryAdd(app, Unknown(app, "", CacheReason.MissingApp));
                        return;
                    }

                    try
                    {
                        var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(
                            _downloadArgs,
                            game.Depots,
                            loopToken);
                        loopToken.ThrowIfCancellationRequested();

                        // Check if game has no depots for the selected OS
                        if (filteredDepots.Count == 0 && game.Depots.Count > 0)
                        {
                            if (versionTwo)
                                statuses.TryAdd(app, Unknown(app, game.Name, CacheReason.UnsupportedOs));
                            return;
                        }

                        if (filteredDepots.Count == 0)
                        {
                            if (versionTwo)
                                statuses.TryAdd(app, Unknown(app, game.Name, CacheReason.NoContent));
                            return;
                        }

                        var requiredDepotCount = filteredDepots.Count;
                        await _depotHandler.BuildLinkedDepotInfoAsync(filteredDepots, loopToken);
                        loopToken.ThrowIfCancellationRequested();
                        if (filteredDepots.Count != requiredDepotCount)
                        {
                            if (versionTwo)
                                statuses.TryAdd(app, Unknown(app, game.Name, CacheReason.LinkedDepotUnavailable));
                            return;
                        }

                        if (filteredDepots.Any(depot => !depot.ManifestId.HasValue || depot.ManifestId.Value == 0))
                        {
                            if (versionTwo)
                                statuses.TryAdd(app, Unknown(app, game.Name, CacheReason.ManifestUnavailable));
                            return;
                        }

                        var authority = versionTwo ? authorityByApp![app] : CacheAuthority.Snapshot;
                        IReadOnlyCollection<string> suppliedPairs = authority == CacheAuthority.Empty
                            ? Array.Empty<string>()
                            : cachedManifests;
                        var suppliedPairsMatch = _depotHandler.AppIsUpToDate(filteredDepots, suppliedPairs);
                        CacheOutcome outcome;
                        CacheReason? reason = null;
                        if (authority == CacheAuthority.Absent)
                        {
                            if (suppliedPairsMatch || _depotHandler.AppIsUpToDate(filteredDepots))
                                outcome = CacheOutcome.Current;
                            else
                            {
                                outcome = CacheOutcome.Unknown;
                                reason = CacheReason.NoCacheEvidence;
                            }
                        }
                        else
                        {
                            outcome = suppliedPairsMatch ? CacheOutcome.Current : CacheOutcome.Outdated;
                        }

                        if (outcome == CacheOutcome.Unknown)
                        {
                            if (versionTwo)
                                statuses.TryAdd(app, Unknown(app, game.Name, reason!.Value));
                            return;
                        }

                        var outdatedDepots = new List<OutdatedDepot>();
                        if (outcome == CacheOutcome.Outdated)
                        {
                            foreach (var depot in filteredDepots)
                            {
                                var currentManifest = depot.ManifestId!.Value;
                                if (!cachedManifests.Contains($"{depot.DepotId}:{currentManifest}"))
                                {
                                    var storedManifests = cachedByDepot.GetValueOrDefault(depot.DepotId);
                                    outdatedDepots.Add(new OutdatedDepot
                                    {
                                        DepotId = depot.DepotId,
                                        CachedManifest = storedManifests is { Length: 1 } ? storedManifests[0] : 0,
                                        CurrentManifest = currentManifest
                                    });
                                }
                            }
                        }

                        long downloadSize = 0;
                        if (!versionTwo && outdatedDepots.Count > 0)
                        {
                            var outdatedDepotIds = outdatedDepots.Select(d => d.DepotId).ToHashSet();
                            var depotsToDownload = filteredDepots.Where(d => outdatedDepotIds.Contains(d.DepotId)).ToList();
                            var (chunks, skippedDepots) = await _depotHandler.BuildChunkDownloadQueueAsync(
                                depotsToDownload,
                                loopToken);
                            downloadSize = chunks.Sum(e => e.CompressedLength);

                            // The depots stay listed as outdated, they just have no size to add, so say so rather than
                            // letting the total quietly come up short
                            if (skippedDepots.Any())
                            {
                                _ansiConsole.LogMarkupError($"Could not size {skippedDepots.Count} depots for {game.Name} ({game.AppId}), the download size is incomplete");
                            }
                        }

                        loopToken.ThrowIfCancellationRequested();
                        statuses.TryAdd(app, new AppCacheStatus
                        {
                            AppId = app,
                            Name = game.Name,
                            IsUpToDate = outcome == CacheOutcome.Current,
                            Outcome = outcome,
                            DownloadSize = downloadSize,
                            OutdatedDepots = outdatedDepots
                        });
                    }
                    catch (OperationCanceledException) when (loopToken.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (SteamConnectionException ex) when (ex.Failure != null)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _ansiConsole.LogMarkupError($"Failed to check cache status for {game.Name} ({game.AppId})");
                        FileLogger.LogException($"Failed to check cache status for {game.Name}", ex);
                        if (versionTwo)
                            statuses.TryAdd(app, Unknown(app, game.Name, CacheReason.InspectionFailed));
                    }
                });
            }
            catch (OperationCanceledException) when (reserveCancellation?.IsCancellationRequested == true
                && !cancellationToken.IsCancellationRequested)
            {
                deadlineReached = true;
            }
            finally
            {
                if (preparationHeld)
                    _preparation.Release();
            }

            return BuildResult();
        }

        #endregion

        public async Task<List<AppInfo>> GetAllAvailableAppsAsync(
            CancellationToken cancellationToken = default)
        {
            await _preparation.WaitAsync(cancellationToken);
            try
            {
                var ownedGameIds = _steam3.LicenseManager.AllOwnedAppIds;

                // Loading app metadata from steam, skipping related DLC apps
                await _appInfoHandler.RetrieveAppMetadataAsync(
                    ownedGameIds,
                    getRecentlyPlayedMetadata: true,
                    cancellationToken);
                var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(
                    ownedGameIds,
                    cancellationToken);

                return availableGames;
            }
            finally { _preparation.Release(); }
        }

        /// <summary>
        /// Clears in-memory caches for app metadata.
        /// Should be called when manifest cache is cleared to ensure consistency.
        /// </summary>
        public void ClearAppInfoCache()
        {
            if (!_preparation.Wait(0)) throw new InvalidOperationException("Catalog preparation is active.");
            try
            {
                _appInfoHandler.ClearLoadedAppInfos();
            }
            finally { _preparation.Release(); }
        }

        private async Task PrintUnownedAppsAsync(
            List<uint> distinctAppIds,
            CancellationToken cancellationToken)
        {
            await _preparation.WaitAsync(cancellationToken);
            try
            {
                // Write out any apps that can't be downloaded as a warning message, so users can know that they were skipped
                AppInfo[] unownedApps = await Task.WhenAll(distinctAppIds.Where(e => !_steam3.LicenseManager.AccountHasAppAccess(e))
                                                                         .Select(e => _appInfoHandler.GetAppInfoAsync(e, cancellationToken)));
                _prefillSummaryResult.UnownedAppsSkipped = unownedApps.Length;


                if (unownedApps.Empty())
                {
                    return;
                }

                var table = new Table { Border = TableBorder.MinimalHeavyHead };
                // Header
                table.AddColumn(new TableColumn(White("App")));

                // Rows
                foreach (var app in unownedApps.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
                {
                    table.AddRow($"[link=https://store.steampowered.com/app/{app.AppId}]🔗[/] {White(app.Name)}");
                }

                _ansiConsole.MarkupLine("");
                _ansiConsole.MarkupLine(LightYellow($" Warning!  Found {Magenta(unownedApps.Length)} unowned apps!  They will be excluded from this prefill run..."));
                _ansiConsole.Write(table);
            }
            finally { _preparation.Release(); }
        }

    }
}
