using OpWarden.Core.Agent;
using OpWarden.SessionAgent;

// The session agent (spec glossary): renders prompts and notifications in the
// interactive user's session and holds no state. `--pipe <name>` points it at a broker
// on another pipe, for development beside an installed broker.

var pipeName = args is ["--pipe", var name] ? name : AgentProtocol.DefaultPipeName;
try
{
    return new AgentApp(pipeName).Run();
}
catch (Exception e)
{
    AgentLog.Write($"session agent failed: {e}");
    return 1;
}
