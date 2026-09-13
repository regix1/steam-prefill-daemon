using SteamPrefill.Api;
using LancachePrefill.Common;
using Xunit;

namespace SteamPrefill.Test;

[Collection("SteamAccountFile")]
public sealed class PrefillRunTests
{
    [Fact]
    public async Task DrainRetainsRequestsRegisteredByPendingWork()
    {
        var protocol = PrefillProtocol.FromEnvironment(30);
        var options = protocol.Capture(new RunOptions { AppIds = new[] { "1" }, MaxConcurrency = 1 });
        using var budget = new RequestBudget(30);
        var claims = new ItemClaims();
        var run = new PrefillRun(options, new RunProgress(Guid.NewGuid().ToString(), protocol.DaemonInstanceId, options), budget, claims);
        var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var nested = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        run.Track(first.Task);
        run.Hold(claims.TryClaim(run.OperationId, new[] { "app:1" })!);
        var drain = run.ReleaseAsync();
        run.Track(nested.Task);
        first.SetResult();
        try
        {
            await Assert.ThrowsAsync<TimeoutException>(() => drain.WaitAsync(TimeSpan.FromMilliseconds(50)));
            Assert.Null(claims.TryClaim("other", new[] { "app:1" }));
        }
        finally
        {
            nested.SetResult();
            await drain.WaitAsync(TimeSpan.FromSeconds(5));
        }
        using var released = claims.TryClaim("other", new[] { "app:1" });
        Assert.NotNull(released);
    }

    [Fact]
    public async Task LimitsAndInstanceRemainStableUntilRestart()
    {
        var previous = Environment.GetEnvironmentVariable("PREFILL_MAX_RUNS");
        try
        {
            Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", null);
            using var commands = new SocketCommandInterface(0);
            var first = Assert.IsType<StatusData>((await ConcurrentPrefillTests.InvokeAsync(commands, new CommandRequest { Type = "status" })).Data);
            Assert.Equal(4, first.MaxConcurrentRuns);
            Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", "16");
            var unchanged = Assert.IsType<StatusData>((await ConcurrentPrefillTests.InvokeAsync(commands, new CommandRequest { Type = "status" })).Data);
            Assert.Equal(4, unchanged.MaxConcurrentRuns);
            Assert.Equal(first.DaemonInstanceId, unchanged.DaemonInstanceId);
            using var restarted = new SocketCommandInterface(0);
            var next = Assert.IsType<StatusData>((await ConcurrentPrefillTests.InvokeAsync(restarted, new CommandRequest { Type = "status" })).Data);
            Assert.Equal(16, next.MaxConcurrentRuns);
            Assert.NotEqual(first.DaemonInstanceId, next.DaemonInstanceId);
        }
        finally { Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", previous); }
    }

    [Theory]
    [InlineData("0")]
    [InlineData("17")]
    [InlineData("several")]
    public void InvalidRunLimitRejectsStartup(string value)
    {
        var previous = Environment.GetEnvironmentVariable("PREFILL_MAX_RUNS");
        try
        {
            Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", value);
            Assert.Throws<ArgumentException>(() => new SocketCommandInterface(0));
        }
        finally { Environment.SetEnvironmentVariable("PREFILL_MAX_RUNS", previous); }
    }
}
