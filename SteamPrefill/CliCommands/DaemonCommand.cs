using SteamPrefill.Api;

namespace SteamPrefill.CliCommands;

[UsedImplicitly]
[Command("daemon", Description = "Run in daemon mode, accepting commands via files. " +
                                 "Ideal for Docker containers and web integration.")]
public class DaemonCommand : ICommand
{
    [CommandOption("commands-dir", 'c',
        Description = "Directory to watch for command files",
        EnvironmentVariable = "PREFILL_COMMANDS_DIR")]
    public string CommandsDir { get; init; } = "/commands";

    [CommandOption("responses-dir", 'r',
        Description = "Directory to write response files",
        EnvironmentVariable = "PREFILL_RESPONSES_DIR")]
    public string ResponsesDir { get; init; } = "/responses";

    public async ValueTask ExecuteAsync(IConsole console)
    {
        var ansiConsole = console.CreateAnsiConsole();

        ansiConsole.MarkupLine($"""
            [cyan]╔═══════════════════════════════════════════════════════════╗[/]
            [cyan]║[/]              [bold]SteamPrefill Daemon Mode[/]                   [cyan]║[/]
            [cyan]╚═══════════════════════════════════════════════════════════╝[/]

            [dim]This mode allows controlling SteamPrefill via file-based commands.[/]
            [dim]Write JSON command files to the commands directory.[/]
            [dim]Responses will be written to the responses directory.[/]

            """);

        using var cts = new CancellationTokenSource();

        // Handle Ctrl+C gracefully
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            ansiConsole.MarkupLine("\n[yellow]Shutdown signal received...[/]");
            cts.Cancel();
        };

        try
        {
            await DaemonMode.RunFileBasedAsync(CommandsDir, ResponsesDir, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Expected when cancelled
        }
    }
}
