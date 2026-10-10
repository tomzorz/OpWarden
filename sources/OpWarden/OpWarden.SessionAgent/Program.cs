using OpWarden.Core.Agent;
using OpWarden.SessionAgent;

// The session agent (spec glossary): renders prompts and notifications in the
// interactive user's session and holds no state. `--pipe <name>` points it at a broker
// on another pipe, for development beside an installed broker.

var pipeName = args is ["--pipe", var name] ? name : AgentProtocol.DefaultPipeName;

// One session agent per broker pipe in this logon session: a second copy, from a
// double start or a stale logon entry, would only be refused by the broker's pin.
using var single = new Mutex(true, $@"Local\OpWarden.SessionAgent.{pipeName}", out var first);
if (!first) return 0;

try
{
    return new AgentApp(pipeName).Run();
}
catch (Exception e)
{
    AgentLog.Write($"session agent failed: {e}");
    return 1;
}
