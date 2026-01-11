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
                ║              SteamPrefill Daemon Mode                     ║
                ║                  v{ThisAssembly.Info.InformationalVersion,-20}             ║
                ╚═══════════════════════════════════════════════════════════╝

                This application runs as a daemon, communicating via SignalR.
                It connects to the Lancache Manager API for real-time control.

                """);

            // Get session ID from environment variable (required)
            var sessionId = Environment.GetEnvironmentVariable("PREFILL_SESSION_ID");
            if (string.IsNullOrEmpty(sessionId))
            {
                Console.WriteLine("ERROR: PREFILL_SESSION_ID environment variable is required");
                return 1;
            }

            // Get or auto-detect API URL
            var apiUrl = DaemonMode.AutoDetectApiUrl();
            if (string.IsNullOrEmpty(apiUrl))
            {
                Console.WriteLine("ERROR: Could not determine API URL. Set LANCACHE_API_URL environment variable.");
                return 1;
            }

            using var cts = new CancellationTokenSource();

            // Handle Ctrl+C gracefully
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Console.WriteLine("\nShutdown signal received...");
                cts.Cancel();
            };

            await DaemonMode.RunSignalRAsync(apiUrl, sessionId, cts.Token);
            
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
        if (args.Any(e => e.Contains("--debug")))
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