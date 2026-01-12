using SteamPrefill.Api;

namespace SteamPrefill.Handlers
{
    public sealed class DownloadHandler : IDisposable
    {
        private readonly IAnsiConsole _ansiConsole;
        private readonly CdnPool _cdnPool;
        private readonly HttpClient _client;
        private readonly IPrefillProgress _progress;

        /// <summary>
        /// The URL/IP Address where the Lancache has been detected.
        /// </summary>
        private string _lancacheAddress;

        public DownloadHandler(IAnsiConsole ansiConsole, CdnPool cdnPool, IPrefillProgress? progress = null)
        {
            _ansiConsole = ansiConsole;
            _cdnPool = cdnPool;
            _progress = progress ?? NullProgress.Instance;

            // Configure SocketsHttpHandler with connection pooling settings
            var handler = new SocketsHttpHandler
            {
                // Connection pool settings to keep connections alive longer
                PooledConnectionLifetime = TimeSpan.FromMinutes(10),
                PooledConnectionIdleTimeout = TimeSpan.FromMinutes(5),
                // Allow more concurrent connections per server
                MaxConnectionsPerServer = 100
            };

            _client = new HttpClient(handler);
            // Lancache requires this user agent in order to correctly identify and cache Valve's content servers
            _client.DefaultRequestHeaders.Add("User-Agent", "Valve/Steam HTTP Client 1.0");
            // Set a reasonable overall timeout (individual request timeouts are handled separately)
            _client.Timeout = TimeSpan.FromMinutes(10);
        }

        public async Task InitializeAsync()
        {
            if (_lancacheAddress == null)
            {
                _lancacheAddress = await LancacheIpResolver.ResolveLancacheIpAsync(_ansiConsole, AppConfig.SteamTriggerDomain);
            }
        }

        /// <summary>
        /// Attempts to download all queued requests.  If all downloads are successful, will return true.
        /// In the case of any failed downloads, the failed downloads will be retried up to 3 times.  If the downloads fail 3 times, then
        /// false will be returned
        /// </summary>
        /// <returns>True if all downloads succeeded.  False if any downloads failed 3 times in a row.</returns>
        public async Task<bool> DownloadQueuedChunksAsync(List<QueuedRequest> queuedRequests, DownloadArguments downloadArgs,
                                                          uint appId = 0, string? appName = null, CancellationToken cancellationToken = default)
        {
            await InitializeAsync();

            int retryCount = 0;
            var failedRequests = new ConcurrentBag<QueuedRequest>();
            await _ansiConsole.CreateSpectreProgress(downloadArgs.TransferSpeedUnit).StartAsync(async ctx =>
            {
                // Run the initial download - use Force flag to bypass Lancache's cache
                failedRequests = await AttemptDownloadAsync(ctx, "Downloading..", queuedRequests, downloadArgs,
                    forceRecache: downloadArgs.Force, appId: appId, appName: appName, cancellationToken: cancellationToken);

                // Handle any failed requests - always force recache on retry
                while (failedRequests.Any() && retryCount < 2)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    retryCount++;
                    failedRequests = await AttemptDownloadAsync(ctx, $"Retrying  {retryCount}..", failedRequests.ToList(), downloadArgs,
                        forceRecache: true, appId: appId, appName: appName, cancellationToken: cancellationToken);
                }
            });

            // Handling final failed requests
            if (failedRequests.IsEmpty)
            {
                return true;
            }

            _ansiConsole.LogMarkupError($"Download failed! {LightYellow(failedRequests.Count)} requests failed unexpectedly, see {LightYellow("app.log")} for more details.");
            _ansiConsole.WriteLine();

            // Web requests frequently fail due to transient errors, so displaying all errors to the user is unnecessary or even confusing.
            // However, if a request fails repeatedly then there might be an underlying issue preventing success.
            // The number of failures could approach in the thousands or even more, so rather than spam the console
            // we will instead log them as a batch to app.log
            foreach (var failedRequest in failedRequests)
            {
                FileLogger.LogExceptionNoStackTrace($"Request /depot/{failedRequest.DepotId}/chunk/{failedRequest.ChunkId} failed", failedRequest.LastFailureReason);
            }
            return false;
        }

        //TODO I don't like the number of parameters here, should maybe rethink the way this is written.
        /// <summary>
        /// Attempts to download the specified requests.  Returns a list of any requests that have failed for any reason.
        /// </summary>
        /// <param name="forceRecache">When specified, will cause the cache to delete the existing cached data for a request, and re-download it again.</param>
        /// <returns>A list of failed requests</returns>
        public async Task<ConcurrentBag<QueuedRequest>> AttemptDownloadAsync(ProgressContext ctx, string taskTitle, List<QueuedRequest> requestsToDownload,
                                                                                DownloadArguments downloadArgs, bool forceRecache = false,
                                                                                uint appId = 0, string? appName = null, CancellationToken cancellationToken = default)
        {
            double requestTotalSize = requestsToDownload.Sum(e => e.CompressedLength);
            var progressTask = ctx.AddTask(taskTitle, new ProgressTaskSettings { MaxValue = requestTotalSize });

            var failedRequests = new ConcurrentBag<QueuedRequest>();
            long bytesDownloaded = 0;
            var startTime = DateTime.UtcNow;
            var lastProgressReport = DateTime.MinValue;
            var progressThrottle = TimeSpan.FromMilliseconds(500);
            
            // Per-request timeout to prevent indefinite hangs (2 minutes should be plenty for any chunk)
            var perRequestTimeout = TimeSpan.FromMinutes(2);

            var cdnServer = _cdnPool.TakeConnection();
            await Parallel.ForEachAsync(requestsToDownload, new ParallelOptions { MaxDegreeOfParallelism = downloadArgs.MaxConcurrentRequests, CancellationToken = cancellationToken }, body: async (request, ct) =>
            {
                // Create a linked cancellation token with a per-request timeout
                // This ensures that individual requests don't hang indefinitely even if the main token doesn't have a timeout
                using var requestTimeoutCts = new CancellationTokenSource(perRequestTimeout);
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, requestTimeoutCts.Token);
                var requestCt = linkedCts.Token;
                
                try
                {
                    var url = $"http://{_lancacheAddress}/depot/{request.DepotId}/chunk/{request.ChunkId}";
                    if (forceRecache)
                    {
                        url += "?nocache=1";
                    }
                    using var requestMessage = new HttpRequestMessage(HttpMethod.Get, url);
                    requestMessage.Headers.Host = cdnServer.Host;

                    using var response = await _client.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, requestCt);
                    response.EnsureSuccessStatusCode();
                    using Stream responseStream = await response.Content.ReadAsStreamAsync(requestCt);

                    // Use larger buffer for more efficient reads (64KB instead of 4KB)
                    var buffer = new byte[65536];
                    // Don't save the data anywhere, so we don't have to waste time writing it to disk.
                    while (await responseStream.ReadAsync(buffer, requestCt) != 0)
                    {
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    // Main cancellation requested - don't add to failed requests, just exit
                    throw;
                }
                catch (OperationCanceledException) when (requestTimeoutCts.IsCancellationRequested)
                {
                    // Per-request timeout - treat as a failure that can be retried
                    request.LastFailureReason = new TimeoutException($"Request timed out after {perRequestTimeout.TotalSeconds} seconds");
                    failedRequests.Add(request);
                }
                catch (Exception e)
                {
                    request.LastFailureReason = e;
                    failedRequests.Add(request);
                }
                progressTask.Increment(request.CompressedLength);

                // Report progress via IPrefillProgress (throttled)
                var downloaded = Interlocked.Add(ref bytesDownloaded, request.CompressedLength);
                var now = DateTime.UtcNow;
                if (now - lastProgressReport >= progressThrottle)
                {
                    lastProgressReport = now;
                    var elapsed = now - startTime;
                    var bytesPerSecond = elapsed.TotalSeconds > 0 ? downloaded / elapsed.TotalSeconds : 0;

                    _progress.OnDownloadProgress(new DownloadProgressInfo
                    {
                        AppId = appId,
                        AppName = appName ?? $"App {appId}",
                        TotalBytes = (long)requestTotalSize,
                        BytesDownloaded = downloaded,
                        BytesPerSecond = bytesPerSecond,
                        Elapsed = elapsed
                    });
                }
            });

            //TODO In the scenario where a user still had all requests fail, potentially display a warning that there is an underlying issue
            // Only return the connections for reuse if there were no errors
            if (failedRequests.IsEmpty)
            {
                _cdnPool.ReturnConnection(cdnServer);
            }

            // Making sure the progress bar is always set to its max value, in-case some unexpected error leaves the progress bar showing as unfinished
            progressTask.Increment(progressTask.MaxValue);
            return failedRequests;
        }

        public void Dispose()
        {
            _client?.Dispose();
        }
    }
}