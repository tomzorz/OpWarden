using System.Windows;
using OpWarden.Core.Agent;
using OpWarden.Core.Management;

namespace OpWarden.SessionAgent;

/// <summary>
/// The session agent (spec glossary): prompts, toasts and the tray icon in the
/// interactive user's session, holding no state of its own.
/// </summary>
/// <remarks>
/// <code>
///   OpWarden.SessionAgent.exe [--pipe NAME] [--manage-pipe NAME] [--open WINDOW]...   the session agent
///   OpWarden.SessionAgent.exe --manage [--manage-pipe NAME]                           the rules window, elevated
/// </code>
/// The pipe names point it at a broker on other pipes, for development beside an
/// installed broker and for the tests. --open status, audit or rules opens that window at
/// start, so the tests and a reviewer can see one without clicking the tray.
/// </remarks>
internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var options = AgentOptions.Parse(args);
        try
        {
            return options.Manage ? RunRulesEditor(options) : RunAgent(options);
        }
        catch (Exception e)
        {
            AgentLog.Write($"session agent failed: {e}");
            return 1;
        }
    }

    private static int RunAgent(AgentOptions options)
    {
        // One session agent per broker pipe in this logon session: a second copy, from a
        // double start or a stale logon entry, would only be refused by the broker's pin.
        using var single = new Mutex(true, $@"Local\OpWarden.SessionAgent.{options.AgentPipe}", out var first);
        if (!first) return 0;

        var app = new App { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        using var host = new AgentHost(app, options);
        host.Start();
        return app.Run();
    }

    /// <summary>
    /// The elevated copy the rules window starts for editing (REQ-TRUST-5): only the rules
    /// window, which edits, and nothing that prompts.
    /// </summary>
    private static int RunRulesEditor(AgentOptions options)
    {
        var app = new App { ShutdownMode = ShutdownMode.OnMainWindowClose };
        var window = new RulesWindow(new ManagementClient(options.ManagementPipe), options);
        return app.Run(window);
    }
}

/// <param name="Manage">True for the elevated rules editor rather than the session agent.</param>
/// <param name="Open">Windows to open at start: status, audit, rules.</param>
internal sealed record AgentOptions(string AgentPipe, string ManagementPipe, bool Manage, IReadOnlyList<string> Open)
{
    public static AgentOptions Parse(IReadOnlyList<string> args)
    {
        var options = new AgentOptions(AgentProtocol.DefaultPipeName, ManagementProtocol.DefaultPipeName, false, []);
        for (var i = 0; i < args.Count; i++)
        {
            options = args[i] switch
            {
                "--pipe" when i + 1 < args.Count => options with { AgentPipe = args[++i] },
                "--manage-pipe" when i + 1 < args.Count => options with { ManagementPipe = args[++i] },
                "--manage" => options with { Manage = true },
                "--open" when i + 1 < args.Count => options with { Open = [.. options.Open, args[++i]] },
                _ => options,
            };
        }

        return options;
    }

    /// <summary>
    /// The arguments that start another copy on the same pipes.
    /// </summary>
    public string PipeArguments => $"--pipe {AgentPipe} --manage-pipe {ManagementPipe}";
}
