namespace OpWarden.Core.CommandLine;

/// <summary>
/// One flag of the op CLI. A flag that does not take a value can still be given one
/// with <c>--flag=value</c>, the way cobra handles booleans and optional values.
/// </summary>
internal sealed record Flag(string Long, char? Short, bool TakesValue);

/// <summary>
/// A command the classifier knows. <paramref name="Flags"/> lists the command's own
/// flags; it is complete only where <paramref name="ParsesPath"/> is true, because the
/// secret path is read from those commands' positionals and flag values, and a flag
/// table with a hole in it misaligns them.
/// </summary>
internal sealed record CommandSpec(string Name, OpAction Action, IReadOnlyList<Flag> Flags, bool ParsesPath);

/// <summary>
/// A command group such as <c>item</c>, with the action for subcommands it does not list.
/// </summary>
internal sealed record CommandGroup(OpAction OtherSubcommands, IReadOnlyDictionary<string, CommandSpec> Subcommands);

/// <summary>
/// The op CLI's command tree and flags as far as classification needs them.
/// </summary>
/// <remarks>
/// Taken from the op CLI's own <c>--help</c> output (version 2.38) and mapped to actions
/// by spec section 6. Anything missing classifies as <see cref="OpAction.Unknown"/>,
/// which prompts; a new op CLI subcommand therefore costs a prompt, never a free pass.
/// </remarks>
internal static class OpCommands
{
    // The op CLI's aliases, from its help output: `delete` also answers to `remove`
    // and `rm`, `list` to `ls`. Declared first: the tables below read it while they
    // initialise.
    private static readonly Dictionary<string, string[]> Aliases = new()
    {
        ["delete"] = ["remove", "rm"],
        ["list"] = ["ls"],
    };

    public static IReadOnlyList<Flag> GlobalFlags { get; } =
    [
        Value("account"), Value("config"), Value("encoding"), Value("format"), Value("session"),
        Switch("cache"), Switch("debug"), Switch("help", 'h'), Switch("iso-timestamps"), Switch("no-color"), Switch("version", 'v'),
    ];

    public static IReadOnlyDictionary<string, CommandSpec> TopLevel { get; } = new Dictionary<string, CommandSpec>
    {
        ["read"] = new("read", OpAction.Read, [Value("file-mode"), Value("out-file", 'o'), Switch("force", 'f'), Switch("no-newline", 'n')], true),
        ["run"] = new("run", OpAction.Run, [Value("env-file"), Switch("no-masking")], true),
        ["inject"] = new("inject", OpAction.Run, [Value("file-mode"), Value("in-file", 'i'), Value("out-file", 'o'), Switch("force", 'f')], true),
        ["signin"] = new("signin", OpAction.Meta, [], false),
        ["signout"] = new("signout", OpAction.Meta, [], false),
        ["whoami"] = new("whoami", OpAction.Meta, [], false),
    };

    public static IReadOnlyDictionary<string, CommandGroup> Groups { get; } = new Dictionary<string, CommandGroup>
    {
        ["item"] = new(OpAction.Unknown, WithAliases(
        [
            new("item get", OpAction.Read, [Value("fields"), Value("vault"), Switch("include-archive"), Switch("otp"), Switch("reveal"), Switch("share-link")], true),
            new("item list", OpAction.Read, [Value("categories"), Value("tags"), Value("vault"), Switch("favorite"), Switch("include-archive"), Switch("long")], true),
            new("item create", OpAction.Write, [Value("category"), Value("tags"), Value("template"), Value("title"), Value("url"), Value("vault"), Switch("dry-run"), Switch("favorite"), Switch("generate-password"), Switch("reveal"), Switch("ssh-generate-key")], true),
            new("item edit", OpAction.Write, [Value("tags"), Value("template"), Value("title"), Value("url"), Value("vault"), Switch("dry-run"), Switch("favorite"), Switch("generate-password"), Switch("reveal")], true),
            new("item delete", OpAction.Delete, [Value("vault"), Switch("archive")], true),
        ])),
        ["document"] = new(OpAction.Unknown, WithAliases(
        [
            new("document get", OpAction.Read, [Value("file-mode"), Value("out-file", 'o'), Value("vault"), Switch("force"), Switch("include-archive")], true),
            new("document create", OpAction.Write, [Value("file-name"), Value("tags"), Value("title"), Value("vault")], true),
            new("document edit", OpAction.Write, [Value("file-name"), Value("tags"), Value("title"), Value("vault")], true),
            new("document delete", OpAction.Delete, [Value("vault"), Switch("archive")], true),
        ])),
        ["user"] = new(OpAction.Manage, WithAliases([new("user get", OpAction.Read, [], false)])),
        ["vault"] = new(OpAction.Manage, WithAliases([new("vault delete", OpAction.Delete, [], true)])),
        ["account"] = new(OpAction.Manage, WithAliases([])),
        ["group"] = new(OpAction.Manage, WithAliases([])),
    };

    private static Flag Value(string name, char? shortName = null) => new(name, shortName, true);

    private static Flag Switch(string name, char? shortName = null) => new(name, shortName, false);

    private static Dictionary<string, CommandSpec> WithAliases(CommandSpec[] specs)
    {
        var map = new Dictionary<string, CommandSpec>();
        foreach (var spec in specs)
        {
            var word = spec.Name[(spec.Name.IndexOf(' ') + 1)..];
            map[word] = spec;
            foreach (var alias in Aliases.GetValueOrDefault(word, [])) map[alias] = spec;
        }

        return map;
    }
}
