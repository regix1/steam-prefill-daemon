using SteamPrefill.Api;

namespace SteamPrefill
{
    public static class Program
    {
        public static async Task<int> Main()
        {
            try
            {
                ParseHiddenFlags();

                Console.WriteLine($"""
                    ╔═══════════════════════════════════════════════════════════╗
                    ║              SteamPrefill Daemon                          ║
                    ║                  v{ThisAssembly.Info.InformationalVersion,-20}             ║
                    ╚═══════════════════════════════════════════════════════════╝

                    """);

                var tcpPortEnv = Environment.GetEnvironmentVariable("PREFILL_TCP_PORT");
                var useTcp = int.TryParse(tcpPortEnv, out var tcpPort) && tcpPort > 0;

                if (!useTcp)
                {
                    Console.WriteLine("Using Unix Domain Socket for reliable, low-latency IPC.");
                    Console.WriteLine();
                }

                // Get socket path from environment or use default in responses dir
                var responsesDir = Environment.GetEnvironmentVariable("PREFILL_RESPONSES_DIR") ?? "/responses";
                var socketPath = Environment.GetEnvironmentVariable("PREFILL_SOCKET_PATH") ??
                                Path.Combine(responsesDir, "daemon.sock");

                using var cts = new CancellationTokenSource();

                Console.CancelKeyPress += (_, e) =>
                {
                    e.Cancel = true;
                    Console.WriteLine("\nShutdown signal received...");
                    cts.Cancel();
                };

                if (useTcp)
                {
                    await DaemonMode.RunTcpAsync(tcpPort, cts.Token);
                }
                else
                {
                    await DaemonMode.RunAsync(socketPath, cts.Token);
                }

                return 0;
            }
            catch (OperationCanceledException)
            {
                // Expected when cancelled
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine($"Fatal error: {e.Message}");
                if (AppConfig.DebugLogs)
                {
                    Console.WriteLine(e.StackTrace);
                }
                return 1;
            }
        }

        /// <summary>
        /// Parses hidden flags that may be useful for debugging/development
        /// </summary>
        private static void ParseHiddenFlags()
        {
            // Have to skip the first argument, since it is the path to the executable
            var args = Environment.GetCommandLineArgs().Skip(1).ToList();

            // Enables SteamKit2 debugging as well as SteamPrefill verbose logs
            if (args.Any(e => e == "--debug"))
            {
                Console.WriteLine($"Using --debug flag. Displaying debug only logging...");
                Console.WriteLine($"Additional debugging files will be output to {AppConfig.DebugOutputDir}");
                AppConfig.DebugLogs = true;
            }

            // Will skip over downloading logic. Will only download manifests
            if (args.Any(e => e.Contains("--no-download")))
            {
                Console.WriteLine($"Using --no-download flag. Will skip downloading chunks...");
                AppConfig.SkipDownloads = true;
            }

            // Skips using locally cached manifests. Saves disk space, at the expense of slower subsequent runs.
            if (args.Any(e => e.Contains("--nocache")) || args.Any(e => e.Contains("--no-cache")))
            {
                Console.WriteLine($"Using --nocache flag. Will always re-download manifests...");
                AppConfig.NoLocalCache = true;
            }

            if (args.Any(e => e.Contains("--cellid")))
            {
                var flagIndex = args.IndexOf("--cellid");
                if (flagIndex >= 0 && flagIndex + 1 < args.Count)
                {
                    var id = args[flagIndex + 1];
                    AppConfig.CellIdOverride = uint.Parse(id);
                    Console.WriteLine($"Using --cellid flag. Will force the usage of cell id {id}");
                }
            }

            if (args.Any(e => e.Contains("--max-threads")))
            {
                var flagIndex = args.IndexOf("--max-threads");
                if (flagIndex >= 0 && flagIndex + 1 < args.Count)
                {
                    var count = args[flagIndex + 1];
                    AppConfig.MaxConcurrencyOverride = int.Parse(count);
                    Console.WriteLine($"Using --max-threads flag. Will download using at most {count} threads");
                }
            }

            // Adding some formatting to logging to make it more readable
            if (AppConfig.DebugLogs || AppConfig.SkipDownloads || AppConfig.NoLocalCache)
            {
                Console.WriteLine();
                Console.WriteLine(new string('─', 60));
            }
        }
    }
}
