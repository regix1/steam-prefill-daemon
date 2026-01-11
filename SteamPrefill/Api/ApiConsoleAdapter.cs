using Spectre.Console;
using Spectre.Console.Rendering;
using System.Text;

namespace SteamPrefill.Api;

/// <summary>
/// An IAnsiConsole adapter that routes console operations through the API interfaces.
/// This allows SteamManager to work without actual console I/O.
/// </summary>
internal sealed class ApiConsoleAdapter : IAnsiConsole
{
    private readonly ISteamAuthProvider _authProvider;
    private readonly IPrefillProgress _progress;
    private readonly StringBuilder _outputBuffer = new();

    public ApiConsoleAdapter(ISteamAuthProvider authProvider, IPrefillProgress progress)
    {
        _authProvider = authProvider;
        _progress = progress;

        // Create a minimal profile
        Profile = new Spectre.Console.Profile(new NullConsoleOutput(), Encoding.UTF8);
    }

    public Spectre.Console.Profile Profile { get; }
    public IAnsiConsoleCursor Cursor => new NullCursor();
    public IAnsiConsoleInput Input => new ApiConsoleInput(_authProvider);
    public IExclusivityMode ExclusivityMode => new NoExclusivityMode();
    public RenderPipeline Pipeline => new();

    public void Clear(bool home)
    {
        _outputBuffer.Clear();
    }

    public void Write(IRenderable renderable)
    {
        // Extract text from renderable and log it
        var text = ExtractText(renderable);
        if (!string.IsNullOrWhiteSpace(text))
        {
            _progress.OnLog(LogLevel.Info, text);
        }
    }

    private string ExtractText(IRenderable renderable)
    {
        // Simple text extraction - handles common cases
        if (renderable is Text textRenderable)
        {
            return textRenderable.ToString() ?? string.Empty;
        }

        if (renderable is Markup markup)
        {
            // Strip markup tags for plain text
            return StripMarkup(markup.ToString() ?? string.Empty);
        }

        if (renderable is Paragraph paragraph)
        {
            return paragraph.ToString() ?? string.Empty;
        }

        // Filter out non-text renderables that don't produce meaningful output
        // ControlCode, Segment, etc. are used for terminal formatting and should be ignored
        var typeName = renderable.GetType().Name;
        if (typeName is "ControlCode" or "Segment" or "ControlSequence")
        {
            return string.Empty;
        }

        // For other types, try to get string representation but filter out type names
        var text = renderable.ToString() ?? string.Empty;

        // If ToString() just returns the type name, it's not useful content
        if (text.StartsWith("Spectre.Console."))
        {
            return string.Empty;
        }

        return text;
    }

    private static string StripMarkup(string text)
    {
        // Simple regex to strip Spectre.Console markup tags
        return System.Text.RegularExpressions.Regex.Replace(text, @"\[/?[^\]]+\]", "");
    }

    /// <summary>
    /// No-op cursor implementation
    /// </summary>
    private class NullCursor : IAnsiConsoleCursor
    {
        public void Move(CursorDirection direction, int steps) { }
        public void SetPosition(int column, int line) { }
        public void Show(bool show) { }
    }

    /// <summary>
    /// Input implementation that routes through auth provider
    /// </summary>
    private class ApiConsoleInput : IAnsiConsoleInput
    {
        private readonly ISteamAuthProvider _authProvider;

        public ApiConsoleInput(ISteamAuthProvider authProvider)
        {
            _authProvider = authProvider;
        }

        public bool IsKeyAvailable() => false;

        public ConsoleKeyInfo? ReadKey(bool intercept)
        {
            // Block until we have input - for now return null
            return null;
        }

        public async Task<ConsoleKeyInfo?> ReadKeyAsync(bool intercept, CancellationToken cancellationToken)
        {
            // Not typically used for our auth flow
            return await Task.FromResult<ConsoleKeyInfo?>(null);
        }
    }

    /// <summary>
    /// No-op exclusivity mode
    /// </summary>
    private class NoExclusivityMode : IExclusivityMode
    {
        public T Run<T>(Func<T> func) => func();
        public async Task<T> RunAsync<T>(Func<Task<T>> func) => await func();
    }

    /// <summary>
    /// No-op console output
    /// </summary>
    private class NullConsoleOutput : IAnsiConsoleOutput
    {
        public TextWriter Writer => TextWriter.Null;
        public bool IsTerminal => false;
        public int Width => 120;
        public int Height => 30;

        public void SetEncoding(Encoding encoding) { }
    }
}
