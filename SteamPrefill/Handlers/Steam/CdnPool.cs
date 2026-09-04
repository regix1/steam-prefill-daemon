namespace SteamPrefill.Handlers.Steam
{
    /// <summary>
    /// This class is primarily responsible for querying the Steam network for available CDN servers,
    /// and managing the current list of available servers.
    /// </summary>
    public sealed class CdnPool
    {
        private readonly IAnsiConsole _ansiConsole;
        private readonly Func<Task<Server[]>> _requestServersAsync;

        private readonly int _minimumServerCount = 5;
        private readonly int _maxRetries = 3;
        private readonly HashSet<string> _discardedHosts = new HashSet<string>();

        public ConcurrentStack<Server> AvailableServerEndpoints = new ConcurrentStack<Server>();

        public CdnPool(IAnsiConsole ansiConsole, Steam3Session steamSession)
        {
            _ansiConsole = ansiConsole;
            _requestServersAsync = async () =>
                (await steamSession.SteamContent.GetServersForSteamPipe()).ToArray();
        }

        /// <summary>
        /// Constructor used by the benchmark run command in order to avoid logging into Steam to get available CDN servers.
        /// Should not be used other than with the benchmark features.
        /// </summary>
        public CdnPool(IAnsiConsole ansiConsole, ConcurrentStack<Server> availableServers)
        {
            _ansiConsole = ansiConsole;
            AvailableServerEndpoints = availableServers;
            _requestServersAsync = () => Task.FromException<Server[]>(
                new InvalidOperationException("The benchmark CDN pool cannot request Steam servers."));
        }

        internal CdnPool(IAnsiConsole ansiConsole, Func<Task<Server[]>> requestServersAsync)
        {
            _ansiConsole = ansiConsole;
            _requestServersAsync = requestServersAsync;
        }

        /// <summary>
        /// Gets a list of available CDN servers from the Steam network.
        /// Required to be called prior to using the class.
        /// </summary>
        /// <exception cref="CdnExhaustionException">If no servers are available for use, this exception will be thrown.</exception>
        public async Task PopulateAvailableServersAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (AvailableServerEndpoints.Count >= _minimumServerCount)
            {
                return;
            }

            _ansiConsole.LogMarkupVerbose($"Requesting available CDNs. Pool currently has {LightYellow(AvailableServerEndpoints.Count)} servers available," +
                                          $" below the desired count of {Cyan(_minimumServerCount)}");

            var retryCount = 0;
            var statusMessageBase = White(" Getting available CDN Servers... ");
            await _ansiConsole.StatusSpinner().StartAsync(statusMessageBase, async task =>
            {
                while (AvailableServerEndpoints.Count < _minimumServerCount && retryCount <= _maxRetries)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await RequestSteamCdnServersAsync(cancellationToken);

                    // Condition prevents the retry message from being displayed on the first run.
                    var retryMessage = retryCount > 0 ? LightYellow($"Retrying {retryCount}") : "";
                    task.Status($"{statusMessageBase} {retryMessage}");
                    await Task.Delay(retryCount * 250, cancellationToken);

                    retryCount++;
                }
            });

            if (retryCount >= _maxRetries && AvailableServerEndpoints.Empty())
            {
                throw new CdnExhaustionException("Request for Steam CDN servers timed out!");
            }
            if (AvailableServerEndpoints.Empty())
            {
                throw new CdnExhaustionException("Unable to get available CDN servers from Steam!");
            }

            AvailableServerEndpoints = AvailableServerEndpoints
                                       // "CDN" type servers always have a load of 0, seem to be the fastest
                                       .OrderByDescending(e => e.Load)
                                       .ToConcurrentStack();

        }

        private async Task RequestSteamCdnServersAsync(CancellationToken cancellationToken)
        {
            var requestTask = Task.Run(_requestServersAsync, CancellationToken.None);
            try
            {
                // GetServersForSteamPipe() sometimes hangs and never times out.  Wrapping the call in another task, so that we can timeout the entire method.
                var returnedServers = await requestTask.WaitAsync(
                    TimeSpan.FromSeconds(15),
                    cancellationToken);

                // Filtering out non-cacheable CDNs.  HTTPS servers are included, as they appear to be able to be manually overridden to HTTP.
                // SteamCache type servers are Valve run.  CDN type servers appear to be ISP run.
                var cacheableServers = returnedServers
                                        .Where(e => (e.Type == "SteamCache" || e.Type == "CDN") && e.AllowedAppIds.Length == 0)
                                        .ToList();

                // Steam keeps listing a server after it has been dropped, so the refill has to leave it out itself.
                var untriedServers = cacheableServers.Where(e => !_discardedHosts.Contains(e.Host)).ToList();
                if (untriedServers.Count == 0)
                {
                    // Every server Steam offers has already failed once.  Trying them again beats a pool that
                    // stays empty until the process restarts.
                    _discardedHosts.Clear();
                    untriedServers = cacheableServers;
                }

                AvailableServerEndpoints.PushRange(untriedServers.ToArray());
                AvailableServerEndpoints = AvailableServerEndpoints
                                            .DistinctBy(e => e.Host)
                                            .ToConcurrentStack();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                ObserveFault(requestTask);
                throw;
            }
            catch (TimeoutException)
            {
                ObserveFault(requestTask);
                // Swallowing timeout exceptions, so that we can retry and see if the next attempt succeeds
            }
        }

        private static void ObserveFault(Task task)
        {
            _ = task.ContinueWith(
                completedTask => _ = completedTask.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        /// <summary>
        /// Attempts to take an available connection from the pool.
        /// Once finished with the connection, it should be returned to the pool using <seealso cref="ReturnConnection"/>
        /// </summary>
        /// <returns>A valid Steam CDN server</returns>
        /// <exception cref="CdnExhaustionException">If no servers are available for use, this exception will be thrown.</exception>
        public Server TakeConnection()
        {
            if (AvailableServerEndpoints.Empty())
            {
                throw new CdnExhaustionException("Available Steam CDN servers exhausted!  No more servers available to retry!  Try again in a few minutes");
            }

            AvailableServerEndpoints.TryPop(out var server);
            _ansiConsole.LogMarkupVerbose($"Using CDN {Cyan(server.Host)}");
            return server;
        }

        /// <summary>
        /// Returns a server to the pool of available servers, to be re-used later.
        /// Only valid server should be returned to the pool.
        /// </summary>
        /// <param name="server">The server that will be re-added to the pool.</param>
        public void ReturnConnection(Server server)
        {
            AvailableServerEndpoints.Push(server);
        }

        /// <summary>
        /// Drops a server that failed for a reason that indicts the server itself, so that it is not handed out
        /// again.  The pool is a stack, so a returned server would otherwise be the very next one taken, and
        /// Steam keeps listing the server, so a refill would otherwise bring it straight back.
        /// Tops the pool back up from Steam when dropping the server left it short.
        /// </summary>
        /// <param name="server">The server that will not be re-added to the pool.</param>
        public async Task DiscardConnectionAsync(Server server, CancellationToken cancellationToken = default)
        {
            _ansiConsole.LogMarkupVerbose($"Dropping CDN {Cyan(server.Host)}, it is not answering");
            _discardedHosts.Add(server.Host);
            await PopulateAvailableServersAsync(cancellationToken);
        }

        /// <summary>
        /// Whether a failed request says the server that answered it is unhealthy, rather than that the request
        /// itself was bad.  A missing chunk or a refused manifest is the same on every server, so it is not.
        /// 508 is left out, as it means the network is misconfigured and the callers treat it as fatal.
        /// </summary>
        public static bool IsServerFault(Exception exception)
        {
            return exception is TimeoutException
                   || exception is TaskCanceledException
                   || (exception is HttpRequestException webException
                       && webException.StatusCode >= HttpStatusCode.InternalServerError
                       && webException.StatusCode != HttpStatusCode.LoopDetected);
        }
    }
}
