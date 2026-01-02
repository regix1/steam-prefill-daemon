using SteamPrefill.Api;

namespace SteamPrefill.CliCommands;

[UsedImplicitly]
[Command("test-client", Description = "Test client for daemon mode - handles encrypted credential exchange")]
public class TestClientCommand : ICommand
{
    [CommandOption("commands-dir", 'c',
        Description = "Directory where daemon watches for commands",
        EnvironmentVariable = "PREFILL_COMMANDS_DIR")]
    public string CommandsDir { get; init; } = "/commands";

    [CommandOption("responses-dir", 'r',
        Description = "Directory where daemon writes responses",
        EnvironmentVariable = "PREFILL_RESPONSES_DIR")]
    public string ResponsesDir { get; init; } = "/responses";

    public async ValueTask ExecuteAsync(IConsole console)
    {
        var ansiConsole = console.CreateAnsiConsole();

        ansiConsole.MarkupLine("[cyan]SteamPrefill Test Client[/]");
        ansiConsole.MarkupLine("[dim]This client handles encrypted credential exchange with the daemon[/]\n");

        using var client = new DaemonClient(CommandsDir, ResponsesDir);

        // Check daemon status
        var status = await client.GetStatusAsync();
        if (status == null)
        {
            ansiConsole.MarkupLine("[red]Daemon not running or status file not found[/]");
            return;
        }

        ansiConsole.MarkupLine($"Daemon status: [yellow]{status.Status}[/]");

        if (status.Status == "logged-in")
        {
            ansiConsole.MarkupLine("[green]Already logged in![/]");
            await ShowMenu(ansiConsole, client);
            return;
        }

        // Start login process
        ansiConsole.MarkupLine("\n[cyan]Starting login process...[/]");

        var challenge = await client.StartLoginAsync(TimeSpan.FromSeconds(10));

        while (challenge != null)
        {
            // Handle device confirmation (Steam Mobile App approval)
            if (challenge.CredentialType == "device-confirmation")
            {
                ansiConsole.MarkupLine("\n[yellow]Steam Guard Mobile Authenticator[/]");
                ansiConsole.MarkupLine("[cyan]Please check your Steam Mobile App and approve the login request.[/]");
                ansiConsole.MarkupLine("[dim]Waiting for approval...[/]");

                // Send acknowledgment that user has been notified
                await client.ProvideCredentialAsync(challenge, "acknowledged");

                // Wait for next challenge or success
                challenge = await client.WaitForChallengeAsync(TimeSpan.FromSeconds(60));
                continue;
            }

            ansiConsole.MarkupLine($"\n[yellow]Credential required: {challenge.CredentialType}[/]");
            if (!string.IsNullOrEmpty(challenge.Email))
            {
                ansiConsole.MarkupLine($"[dim]Email: {challenge.Email}[/]");
            }

            // Prompt for credential based on type
            string credential;
            switch (challenge.CredentialType)
            {
                case "password":
                    credential = ansiConsole.Prompt(
                        new TextPrompt<string>("Enter password:")
                            .Secret());
                    break;
                case "2fa":
                    ansiConsole.MarkupLine("[cyan]Enter the code from your Steam Mobile Authenticator app[/]");
                    credential = ansiConsole.Prompt(
                        new TextPrompt<string>("Enter 2FA code:"));
                    break;
                case "steamguard":
                    ansiConsole.MarkupLine("[cyan]A Steam Guard code has been sent to your email[/]");
                    credential = ansiConsole.Prompt(
                        new TextPrompt<string>("Enter Steam Guard code:"));
                    break;
                default:
                    credential = ansiConsole.Prompt(
                        new TextPrompt<string>($"Enter {challenge.CredentialType}:"));
                    break;
            }

            // Encrypt and send credential
            ansiConsole.MarkupLine("[dim]Encrypting credential...[/]");
            await client.ProvideCredentialAsync(challenge, credential);
            ansiConsole.MarkupLine("[green]Credential sent (encrypted)[/]");

            // Wait for next challenge or success
            ansiConsole.MarkupLine("[dim]Waiting for response...[/]");

            // Check if we need another credential
            challenge = await client.WaitForChallengeAsync(TimeSpan.FromSeconds(30));
        }

        // Check final status
        await Task.Delay(1000);
        status = await client.GetStatusAsync();

        if (status?.Status == "logged-in")
        {
            ansiConsole.MarkupLine("\n[green]Login successful![/]");
            await ShowMenu(ansiConsole, client);
        }
        else
        {
            ansiConsole.MarkupLine($"\n[red]Login may have failed. Status: {status?.Status ?? "unknown"}[/]");
        }
    }

    private async Task ShowMenu(IAnsiConsole ansiConsole, DaemonClient client)
    {
        while (true)
        {
            ansiConsole.WriteLine();
            var choice = ansiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("What would you like to do?")
                    .AddChoices(
                        "Get owned games",
                        "Prefill selected apps",
                        "Prefill all owned games",
                        "Prefill recent games",
                        "Select apps for prefill",
                        "Check status",
                        "Shutdown daemon",
                        "Exit"));

            switch (choice)
            {
                case "Get owned games":
                    await ShowOwnedGames(ansiConsole, client);
                    break;

                case "Prefill selected apps":
                    await RunPrefill(ansiConsole, client, all: false, recent: false);
                    break;

                case "Prefill all owned games":
                    var confirmAll = ansiConsole.Confirm("This will prefill ALL owned games. Continue?", false);
                    if (confirmAll)
                    {
                        await RunPrefill(ansiConsole, client, all: true, recent: false);
                    }
                    break;

                case "Prefill recent games":
                    await RunPrefill(ansiConsole, client, all: false, recent: true);
                    break;

                case "Select apps for prefill":
                    await SelectAppsForPrefill(ansiConsole, client);
                    break;

                case "Check status":
                    var status = await client.GetStatusAsync();
                    ansiConsole.MarkupLine($"Status: [yellow]{status?.Status ?? "unknown"}[/]");
                    break;

                case "Shutdown daemon":
                    await client.ShutdownAsync();
                    ansiConsole.MarkupLine("[yellow]Shutdown command sent[/]");
                    return;

                case "Exit":
                    return;
            }
        }
    }

    private async Task ShowOwnedGames(IAnsiConsole ansiConsole, DaemonClient client)
    {
        try
        {
            ansiConsole.MarkupLine("[dim]Fetching games...[/]");
            var games = await client.GetOwnedGamesAsync();
            ansiConsole.MarkupLine($"[green]Found {games.Count} games[/]");

            var table = new Table();
            table.AddColumn("AppId");
            table.AddColumn("Name");

            foreach (var game in games.Take(20))
            {
                table.AddRow(game.AppId.ToString(), game.Name);
            }

            if (games.Count > 20)
            {
                table.AddRow("...", $"and {games.Count - 20} more");
            }

            ansiConsole.Write(table);
        }
        catch (Exception ex)
        {
            ansiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
        }
    }

    private async Task RunPrefill(IAnsiConsole ansiConsole, DaemonClient client, bool all, bool recent)
    {
        try
        {
            var options = all ? "all owned games" : recent ? "recent games" : "selected apps";
            ansiConsole.MarkupLine($"[cyan]Starting prefill for {options}...[/]");
            ansiConsole.MarkupLine("[dim]This may take a while depending on the number and size of games.[/]");

            var result = await client.PrefillAsync(all: all, recent: recent);

            if (result.Success)
            {
                ansiConsole.MarkupLine($"[green]Prefill completed successfully![/]");
                ansiConsole.MarkupLine($"Total time: {result.TotalTime:hh\\:mm\\:ss}");
            }
            else
            {
                ansiConsole.MarkupLine($"[red]Prefill failed: {result.ErrorMessage}[/]");
            }
        }
        catch (Exception ex)
        {
            ansiConsole.MarkupLine($"[red]Error during prefill: {ex.Message}[/]");
        }
    }

    private async Task SelectAppsForPrefill(IAnsiConsole ansiConsole, DaemonClient client)
    {
        try
        {
            ansiConsole.MarkupLine("[dim]Fetching owned games...[/]");
            var games = await client.GetOwnedGamesAsync();

            if (games.Count == 0)
            {
                ansiConsole.MarkupLine("[yellow]No games found.[/]");
                return;
            }

            // Let user select games
            var selectedGames = ansiConsole.Prompt(
                new MultiSelectionPrompt<OwnedGame>()
                    .Title("Select games to prefill (space to select, enter to confirm):")
                    .PageSize(20)
                    .UseConverter(g => $"{g.Name} ({g.AppId})")
                    .AddChoices(games.OrderBy(g => g.Name)));

            if (selectedGames.Count == 0)
            {
                ansiConsole.MarkupLine("[yellow]No games selected.[/]");
                return;
            }

            var appIds = selectedGames.Select(g => g.AppId).ToList();
            await client.SetSelectedAppsAsync(appIds);

            ansiConsole.MarkupLine($"[green]Selected {appIds.Count} games for prefill.[/]");
            ansiConsole.MarkupLine("[dim]Use 'Prefill selected apps' to start the download.[/]");
        }
        catch (Exception ex)
        {
            ansiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
        }
    }
}
