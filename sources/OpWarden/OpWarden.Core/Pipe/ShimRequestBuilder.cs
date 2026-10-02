using OpWarden.Core.CommandLine;

namespace OpWarden.Core.Pipe;

public static class ShimRequestBuilder
{
    /// <summary>
    /// Classifies an invocation and collects its secret references into the request the
    /// shim sends. The environment is the shim's own, which the op CLI inherits.
    /// </summary>
    public static ShimRequest Build(IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment)
    {
        var parsed = OpArgvParser.Parse(arguments);
        var references = SecretReferenceCollector.Collect(parsed, environment);
        return new ShimRequest(PipeProtocol.Version, arguments, parsed.Command, parsed.Action, parsed.Path, references.References, references.Unknown);
    }
}
