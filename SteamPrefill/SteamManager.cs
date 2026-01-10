using SteamPrefill.Api;

namespace SteamPrefill
{
    public sealed class SteamManager : IDisposable
    {
        private readonly IAnsiConsole _ansiConsole;
        private readonly DownloadArguments _downloadArgs;

        private readonly Steam3Session _steam3;
        private readonly CdnPool _cdnPool;

        private readonly DownloadHandler _downloadHandler;
        private readonly DepotHandler _depotHandler;
        private readonly AppInfoHandler _appInfoHandler;

        private readonly PrefillSummaryResult _prefillSummaryResult = new PrefillSummaryResult();
        private readonly IPrefillProgress _progress;

        public SteamManager(IAnsiConsole ansiConsole, DownloadArguments downloadArgs, ISteamAuthProvider? authProvider = null, IPrefillProgress? progress = null)
        {
            _ansiConsole = ansiConsole;
            _downloadArgs = downloadArgs;
            _progress = progress ?? NullProgress.Instance;

            _steam3 = new Steam3Session(_ansiConsole, authProvider);
            _cdnPool = new CdnPool(_ansiConsole, _steam3);
            _appInfoHandler = new AppInfoHandler(_ansiConsole, _steam3, _steam3.LicenseManager);
            _downloadHandler = new DownloadHandler(_ansiConsole, _cdnPool, _progress);
            _depotHandler = new DepotHandler(_ansiConsole, _steam3, _appInfoHandler, _cdnPool);
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
            _steam3.WaitForLicenseCallback();

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
            _downloadHandler.Dispose();
            _steam3.Dispose();
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
        public async Task DownloadMultipleAppsAsync(bool downloadAllOwnedGames, bool prefillRecentGames,
                                                    int? prefillPopularGames, bool prefillRecentlyPurchasedGames,
                                                    CancellationToken cancellationToken = default)
        {
            // Building out the list of AppIds to download
            var appIdsToDownload = LoadPreviouslySelectedApps();
            if (downloadAllOwnedGames)
            {
                appIdsToDownload.AddRange(_steam3.LicenseManager.AllOwnedAppIds);
            }
            if (prefillRecentGames)
            {
                var recentGames = await _appInfoHandler.GetRecentlyPlayedGamesAsync();
                appIdsToDownload.AddRange(recentGames.Select(e => (uint)e.appid));
            }
            if (prefillPopularGames != null)
            {
                var popularGames = (await SteamChartsService.MostPlayedByDailyPlayersAsync(_ansiConsole))
                                   .Take(prefillPopularGames.Value)
                                   .Select(e => e.AppId);
                appIdsToDownload.AddRange(popularGames);
            }
            if (prefillRecentlyPurchasedGames)
            {
                var recentApps = _steam3.LicenseManager.GetRecentlyPurchasedAppIds(30);
                appIdsToDownload.AddRange(recentApps);

                // Verbose logging for recently purchased games
                await _appInfoHandler.RetrieveAppMetadataAsync(recentApps);
                _ansiConsole.LogMarkupVerbose("[bold yellow]Recently purchased games (last 2 weeks):[/]");
                foreach (var appId in recentApps)
                {
                    var purchaseDate = _steam3.LicenseManager.GetPurchaseDateForApp(appId);
                    var appInfo = await _appInfoHandler.GetAppInfoAsync(appId);
                    _ansiConsole.LogMarkupVerbose($"  {Green(appInfo.Name).PadRight(35)} - Purchased: {LightYellow(purchaseDate.ToLocalTime().ToString("yyyy-MM-dd"))}");
                }
            }

            // AppIds can potentially be added twice when building out the full list of ids
            var distinctAppIds = appIdsToDownload.Distinct().ToList();
            
            // Report progress for metadata retrieval (can be slow for large libraries)
            _progress.OnLog(LogLevel.Info, $"Loading metadata for {distinctAppIds.Count} apps...");
            await _appInfoHandler.RetrieveAppMetadataAsync(distinctAppIds);
            _progress.OnLog(LogLevel.Info, $"Metadata loaded for {distinctAppIds.Count} apps");

            // Whitespace divider
            _ansiConsole.WriteLine();

            var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(distinctAppIds);
            _progress.OnLog(LogLevel.Info, $"Starting prefill of {availableGames.Count} games");
            
            foreach (var app in availableGames)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await DownloadSingleAppAsync(app, cancellationToken);
                }
                catch (Exception e) when (e is LancacheNotFoundException || e is InfiniteLoopException)
                {
                    // We'll want to bomb out the entire process for these exceptions, as they mean we can't prefill any apps at all
                    throw;
                }
                catch (Exception e)
                {
                    // Need to catch any exceptions that might happen during a single download, so that the other apps won't be affected
                    _ansiConsole.LogMarkupLine(Red($"Unexpected download error : {e.Message}  Skipping app..."));
                    _ansiConsole.MarkupLine("");
                    FileLogger.LogException(e);

                    _prefillSummaryResult.FailedApps++;
                }
            }
            await PrintUnownedAppsAsync(distinctAppIds);

            _ansiConsole.LogMarkupLine("Prefill complete!");
            _prefillSummaryResult.RenderSummaryTable(_ansiConsole);
        }

        private async Task DownloadSingleAppAsync(AppInfo appInfo, CancellationToken cancellationToken = default)
        {
            // Filter depots based on specified language/OS/cpu architecture/etc
            var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(_downloadArgs, appInfo.Depots);
            if (filteredDepots.Empty())
            {
                _ansiConsole.LogMarkupLine($"Starting {Cyan(appInfo)}  {LightYellow("No depots to download.  Current arguments filtered all depots")}");
                _progress.OnAppCompleted(
                    new AppDownloadInfo { AppId = appInfo.AppId, Name = appInfo.Name, TotalBytes = 0 },
                    AppDownloadResult.NoDepotsToDownload);
                return;
            }

            await _depotHandler.BuildLinkedDepotInfoAsync(filteredDepots);

            // Get the full file list for each depot, and queue up the required chunks
            // We do this before the up-to-date check so we can report accurate sizes for cached games
            await _cdnPool.PopulateAvailableServersAsync();

            List<QueuedRequest> chunkDownloadQueue = null;
            await _ansiConsole.StatusSpinner().StartAsync("Fetching depot manifests...", async _ => { chunkDownloadQueue = await _depotHandler.BuildChunkDownloadQueueAsync(filteredDepots); });

            var totalBytes = ByteSize.FromBytes(chunkDownloadQueue.Sum(e => e.CompressedLength));

            // Build depot manifest info for cache tracking
            var depotManifests = filteredDepots
                .Where(d => d.ManifestId.HasValue)
                .Select(d => new DepotManifestInfo
                {
                    DepotId = d.DepotId,
                    ManifestId = d.ManifestId!.Value,
                    TotalBytes = 0 // Will be set from chunk queue if downloaded
                })
                .ToList();

            // We will want to re-download the entire app, if any of the depots have been updated
            if (_downloadArgs.Force == false && _depotHandler.AppIsUpToDate(filteredDepots))
            {
                _prefillSummaryResult.AlreadyUpToDate++;
                _progress.OnAppCompleted(
                    new AppDownloadInfo
                    {
                        AppId = appInfo.AppId,
                        Name = appInfo.Name,
                        TotalBytes = (long)totalBytes.Bytes,
                        Depots = depotManifests
                    },
                    AppDownloadResult.AlreadyUpToDate);
                return;
            }

            _ansiConsole.LogMarkupLine($"Starting {Cyan(appInfo)}");

            // Finally run the queued downloads
            var downloadTimer = Stopwatch.StartNew();
            _prefillSummaryResult.TotalBytesTransferred += totalBytes;

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

            var downloadSuccessful = await _downloadHandler.DownloadQueuedChunksAsync(chunkDownloadQueue, _downloadArgs,
                appId: appInfo.AppId, appName: appInfo.Name, cancellationToken: cancellationToken);
            if (downloadSuccessful)
            {
                _depotHandler.MarkDownloadAsSuccessful(filteredDepots);
                _prefillSummaryResult.Updated++;
                _progress.OnAppCompleted(appDownloadInfo, AppDownloadResult.Success);

                // Logging some metrics about the download
                _ansiConsole.LogMarkupLine($"Finished in {LightYellow(downloadTimer.FormatElapsedString())} - {Magenta(totalBytes.CalculateBitrate(downloadTimer))}");
                _ansiConsole.WriteLine();
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
        /// Gets status information for selected apps including download sizes.
        /// </summary>
        public async Task<List<AppStatus>> GetSelectedAppsStatusAsync(List<uint> appIds)
        {
            // Force-refresh app metadata for these specific apps to ensure accurate size calculations
            _appInfoHandler.InvalidateApps(appIds);
            await _appInfoHandler.RetrieveAppMetadataAsync(appIds);
            await _cdnPool.PopulateAvailableServersAsync();

            var appStatuses = new ConcurrentBag<AppStatus>();
            var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(appIds);
            
            _ansiConsole.LogMarkupVerbose($"Getting status for {Magenta(availableGames.Count)} available games out of {Magenta(appIds.Count)} requested");

            // Build OS names string for error messages
            var selectedOsNames = string.Join(", ", _downloadArgs.OperatingSystems.Select(os => os.Name));

            await Parallel.ForEachAsync(availableGames, new ParallelOptions { MaxDegreeOfParallelism = 5 }, async (app, _) =>
            {
                try
                {
                    _ansiConsole.LogMarkupVerbose($"Processing {Cyan(app.Name)}: {app.Depots.Count} depots");
                    var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(_downloadArgs, app.Depots);
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

                    await _depotHandler.BuildLinkedDepotInfoAsync(filteredDepots);

                    var allChunksForApp = await _depotHandler.BuildChunkDownloadQueueAsync(filteredDepots);
                    var downloadSize = allChunksForApp.Sum(e => e.CompressedLength);

                    appStatuses.Add(new AppStatus
                    {
                        AppId = app.AppId,
                        Name = app.Name,
                        DownloadSize = downloadSize,
                        IsUpToDate = _downloadArgs.Force == false && _depotHandler.AppIsUpToDate(filteredDepots)
                    });
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


        /// <summary>
        /// Checks cache status by comparing cached depot manifests against Steam's current manifests.
        /// This allows accurate detection of which apps are truly up-to-date even when daemon restarts.
        /// </summary>
        public async Task<CacheStatusResult> CheckCacheStatusAsync(List<CachedDepotInput> cachedDepots)
        {
            if (cachedDepots.Count == 0)
            {
                return new CacheStatusResult
                {
                    Apps = new List<AppCacheStatus>(),
                    Message = "No cached depots provided"
                };
            }

            // Group cached depots by app ID
            var cachedByApp = cachedDepots
                .GroupBy(d => d.AppId)
                .ToDictionary(g => g.Key, g => g.ToDictionary(d => d.DepotId, d => d.ManifestId));

            var appIds = cachedByApp.Keys.ToList();

            // Force-refresh app metadata for these specific apps to ensure accurate manifest info
            _appInfoHandler.InvalidateApps(appIds);
            await _appInfoHandler.RetrieveAppMetadataAsync(appIds);
            await _cdnPool.PopulateAvailableServersAsync();

            var appStatuses = new ConcurrentBag<AppCacheStatus>();
            var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(appIds);

            _ansiConsole.LogMarkupVerbose($"Checking cache status for {Magenta(availableGames.Count)} available games");

            // Build OS names string for error messages
            var selectedOsNames = string.Join(", ", _downloadArgs.OperatingSystems.Select(os => os.Name));

            await Parallel.ForEachAsync(availableGames, new ParallelOptions { MaxDegreeOfParallelism = 5 }, async (app, _) =>
            {
                try
                {
                    var filteredDepots = await _depotHandler.FilterDepotsToDownloadAsync(_downloadArgs, app.Depots);

                    // Check if game has no depots for the selected OS
                    if (filteredDepots.Count == 0 && app.Depots.Count > 0)
                    {
                        appStatuses.Add(new AppCacheStatus
                        {
                            AppId = app.AppId,
                            Name = app.Name,
                            DownloadSize = 0,
                            IsUpToDate = false,
                            OutdatedDepots = new List<OutdatedDepot>()
                        });
                        return;
                    }

                    await _depotHandler.BuildLinkedDepotInfoAsync(filteredDepots);

                    // Get cached manifests for this app
                    var cachedManifests = cachedByApp.GetValueOrDefault(app.AppId) ?? new Dictionary<uint, ulong>();

                    // Compare each depot's current manifest against cached manifest
                    var outdatedDepots = new List<OutdatedDepot>();
                    long downloadSize = 0;

                    foreach (var depot in filteredDepots)
                    {
                        var currentManifest = depot.ManifestId.Value;
                        var hasCached = cachedManifests.TryGetValue(depot.DepotId, out var cachedManifest);

                        if (!hasCached || cachedManifest != currentManifest)
                        {
                            outdatedDepots.Add(new OutdatedDepot
                            {
                                DepotId = depot.DepotId,
                                CachedManifest = hasCached ? cachedManifest : 0,
                                CurrentManifest = currentManifest
                            });
                        }
                    }

                    // If any depot is outdated, calculate download size for outdated depots
                    if (outdatedDepots.Count > 0)
                    {
                        var outdatedDepotIds = outdatedDepots.Select(d => d.DepotId).ToHashSet();
                        var depotsToDownload = filteredDepots.Where(d => outdatedDepotIds.Contains(d.DepotId)).ToList();
                        var chunks = await _depotHandler.BuildChunkDownloadQueueAsync(depotsToDownload);
                        downloadSize = chunks.Sum(e => e.CompressedLength);
                    }

                    appStatuses.Add(new AppCacheStatus
                    {
                        AppId = app.AppId,
                        Name = app.Name,
                        IsUpToDate = outdatedDepots.Count == 0,
                        DownloadSize = downloadSize,
                        OutdatedDepots = outdatedDepots
                    });
                }
                catch (Exception ex)
                {
                    _ansiConsole.LogMarkupError($"Failed to check cache status for {app.Name} ({app.AppId}): {ex.Message}");
                    FileLogger.LogException($"Failed to check cache status for {app.Name}", ex);

                    appStatuses.Add(new AppCacheStatus
                    {
                        AppId = app.AppId,
                        Name = app.Name,
                        DownloadSize = 0,
                        IsUpToDate = false,
                        OutdatedDepots = new List<OutdatedDepot>()
                    });
                }
            });

            var upToDateCount = appStatuses.Count(a => a.IsUpToDate);
            var needsUpdateCount = appStatuses.Count - upToDateCount;
            var totalDownloadSize = ByteSize.FromBytes(appStatuses.Sum(a => a.DownloadSize));

            return new CacheStatusResult
            {
                Apps = appStatuses.OrderBy(a => a.Name).ToList(),
                Message = $"{upToDateCount} apps up-to-date, {needsUpdateCount} need updates ({totalDownloadSize.ToDecimalString()} to download)"
            };
        }

        #endregion

        public async Task<List<AppInfo>> GetAllAvailableAppsAsync()
        {
            var ownedGameIds = _steam3.LicenseManager.AllOwnedAppIds;

            // Loading app metadata from steam, skipping related DLC apps
            await _appInfoHandler.RetrieveAppMetadataAsync(ownedGameIds, getRecentlyPlayedMetadata: true);
            var availableGames = await _appInfoHandler.GetAvailableGamesByIdAsync(ownedGameIds);

            return availableGames;
        }

        /// <summary>
        /// Clears in-memory caches for app metadata.
        /// Should be called when manifest cache is cleared to ensure consistency.
        /// </summary>
        public void ClearAppInfoCache()
        {
            _appInfoHandler.ClearLoadedAppInfos();
        }

        private async Task PrintUnownedAppsAsync(List<uint> distinctAppIds)
        {
            // Write out any apps that can't be downloaded as a warning message, so users can know that they were skipped
            AppInfo[] unownedApps = await Task.WhenAll(distinctAppIds.Where(e => !_steam3.LicenseManager.AccountHasAppAccess(e))
                                                                     .Select(e => _appInfoHandler.GetAppInfoAsync(e)));
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

    }
}