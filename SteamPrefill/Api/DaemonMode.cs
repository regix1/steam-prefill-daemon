#nullable enable

namespace SteamPrefill.Api;

/// <summary>
/// Runs SteamPrefill in daemon mode using Unix Domain Socket for IPC.
/// This is the recommended way to run SteamPrefill in a Docker container for web integration.
///
/// Features:
/// - Reliable bidirectional communication
/// - Low latency (&lt;1ms)
/// - Works in both host and bridge Docker network modes
/// - Real-time progress streaming
///
/// Security features:
/// - Login required before any commands
/// - Encrypted credential exchange (ECDH + AES-GCM)
/// - Plain text passwords never written to disk
/// - Secure memory handling for credentials
/// </summary>
public static class DaemonMode
{
    /// <summary>
    /// Run in socket-based daemon mode.
    /// Uses Unix Domain Socket for reliable, low-latency bidirectional communication.
    /// </summary>
    /// <param name="socketPath">Path to the Unix socket file (e.g., /responses/daemon.sock)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public static async Task RunAsync(
        string socketPath = "/responses/daemon.sock",
        CancellationToken cancellationToken = default)
    {
        Console.WriteLine(GetUnixStartupMessage(socketPath));

        using var socketInterface = new SocketCommandInterface(socketPath);

        await socketInterface.StartAsync(cancellationToken);

        Console.WriteLine("Daemon started. Waiting for connections...");

        // Keep running until cancelled
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Console.WriteLine("Daemon shutdown requested...");
        }

        await socketInterface.StopAsync();
        Console.WriteLine("Daemon stopped.");
    }

    /// <summary>
    /// Run in TCP-based daemon mode.
    /// Uses TCP for bidirectional communication (useful for Windows Docker Desktop).
    /// </summary>
    public static async Task RunTcpAsync(
        int port,
        CancellationToken cancellationToken = default)
    {
        Console.WriteLine(GetTcpStartupMessage(port));

        using var socketInterface = new SocketCommandInterface(port);

        await socketInterface.StartAsync(cancellationToken);

        Console.WriteLine("Daemon started. Waiting for connections...");

        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Console.WriteLine("Daemon shutdown requested...");
        }

        await socketInterface.StopAsync();
        Console.WriteLine("Daemon stopped.");
    }

    internal static string GetUnixStartupMessage(string socketPath)
        => $"Starting SteamPrefill daemon on socket {socketPath}";

    internal static string GetTcpStartupMessage(int port)
        => $"Starting SteamPrefill daemon on TCP port {port}";
}
