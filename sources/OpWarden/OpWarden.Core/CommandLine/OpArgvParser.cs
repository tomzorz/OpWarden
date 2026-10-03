namespace OpWarden.Core.CommandLine;

/// <summary>
/// Classifies an op CLI argument list (spec section 6) and reads the secret path out
/// of it (REQ-CLAS-9, REQ-CLAS-10).
/// </summary>
/// <remarks>
/// The op CLI parses its arguments with cobra, so this follows cobra's rules: flags may
/// appear anywhere, <c>--name=value</c> and <c>--name value</c> both work for flags
/// that take a value, short flags cluster (<c>-fn</c>, <c>-ofile</c>), and <c>--</c>
/// ends flag parsing.
///
/// The one place this is stricter than cobra is before the command. There, only global
/// flags are accepted; anything else makes the whole invocation unknown. Cobra would
/// skip such a flag by guessing whether it takes a value, and a guess that differs
/// from the op CLI's is a command word read as a flag value, which is a rule evaded.
///
/// Everything here errs toward unknown. An unknown field prompts; a wrong field
/// matches the wrong rule.
/// </remarks>
public static class OpArgvParser
{
    public static ParsedInvocation Parse(IReadOnlyList<string> args)
    {
        var i = 0;
        var globals = new List<(string Name, string? Value)>();
        CommandSpec? spec = null;
        string? groupName = null;
        CommandGroup? group = null;

        while (i < args.Count && spec is null)
        {
            var token = args[i];
            if (IsFlag(token))
            {
                if (!TryReadFlag(args, ref i, OpCommands.GlobalFlags, globals)) return ParsedInvocation.Unresolved;
                continue;
            }

            if (token == "--") return ParsedInvocation.Unresolved;

            i++;
            if (group is null)
            {
                if (OpCommands.TopLevel.TryGetValue(token, out var topLevel)) spec = topLevel;
                else if (OpCommands.Groups.TryGetValue(token, out var found)) (groupName, group) = (token, found);
                else return ParsedInvocation.Unresolved;
            }
            else
            {
                spec = group.Subcommands.TryGetValue(token, out var subcommand)
                    ? subcommand
                    : new CommandSpec($"{groupName} {token}", group.OtherSubcommands, [], false);
            }
        }

        if (spec is null)
        {
            // `op --version` and `op -v` are meta (REQ-CLAS-7); a bare group or a bare
            // `op` prints help and classifies as unknown.
            var versionOnly = group is null && globals.Count > 0 && globals.All(g => g.Name == "version");
            return versionOnly
                ? ParsedInvocation.Unresolved with { Command = "--version", Action = OpAction.Meta }
                : ParsedInvocation.Unresolved with { Command = groupName };
        }

        var table = OpCommands.GlobalFlags.Concat(spec.Flags).ToList();
        var flags = new List<(string Name, string? Value)>();
        var positionals = new List<string>();
        var misaligned = false;
        while (i < args.Count)
        {
            var token = args[i];
            if (token == "--")
            {
                positionals.AddRange(args.Skip(i + 1));
                break;
            }

            if (IsFlag(token))
            {
                if (!TryReadFlag(args, ref i, table, flags)) misaligned = true;
                continue;
            }

            positionals.Add(token);
            i++;
        }

        var invocation = new ParsedInvocation(spec.Name, spec.Action, SecretPath.Unknown, [], false, [], null);
        if (!spec.ParsesPath) return invocation;
        if (misaligned) return invocation with { ReferencesUnknown = true };

        string? Last(string name) => NonEmpty(flags.LastOrDefault(f => f.Name == name).Value);
        IEnumerable<string> All(string name) => flags.Where(f => f.Name == name && f.Value is not null).Select(f => f.Value!);

        invocation = invocation with { OutputFile = Last("out-file") };
        return spec.Name switch
        {
            "read" => ReadInvocation(invocation, positionals),
            "run" => invocation with { EnvFiles = [.. All("env-file")] },
            "inject" => invocation with { TemplateFile = Last("in-file") },
            "item get" => invocation with { Path = new(Last("vault"), ItemArgument(positionals, 1), SingleField(All("fields"))) },
            "item list" => invocation with { Path = new(Last("vault"), null, null) },
            "item create" or "document create" => invocation with { Path = new(Last("vault"), Last("title"), null) },
            "item edit" => invocation with { Path = new(Last("vault"), ItemArgument(positionals, int.MaxValue), null) },
            "item delete" or "document get" or "document delete" => invocation with { Path = new(Last("vault"), ItemArgument(positionals, 1), null) },
            "document edit" => invocation with { Path = new(Last("vault"), ItemArgument(positionals, 2), null) },
            "vault delete" => invocation with { Path = new(ItemArgument(positionals, 1), null, null) },
            _ => invocation,
        };
    }

    private static ParsedInvocation ReadInvocation(ParsedInvocation invocation, List<string> positionals)
    {
        // A `$` in an `op read` argument survived the caller's shell; whether the op
        // CLI expands it is undocumented, so the reference stays unknown.
        var reference = positionals.Count == 1 && !positionals[0].Contains('$') ? SecretReference.TryParse(positionals[0]) : null;
        return reference is null
            ? invocation with { ReferencesUnknown = true }
            : invocation with { Path = reference, ArgumentReferences = [reference] };
    }

    /// <summary>
    /// The item (or vault) named by the first positional. <c>-</c> reads it from standard
    /// input and a share link names it indirectly, so both stay unknown, as does a
    /// positional count the command does not accept.
    /// </summary>
    private static string? ItemArgument(List<string> positionals, int maxPositionals)
    {
        if (positionals.Count == 0 || positionals.Count > maxPositionals) return null;
        var first = positionals[0];
        return first == "-" || first.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ? null : NonEmpty(first);
    }

    /// <summary>
    /// The key for <c>op item get --fields</c>: known only when exactly one field is
    /// asked for by label. <c>type=</c> selects fields by type, so which fields come
    /// back is unknown, and so is the key of a call that returns every field.
    /// </summary>
    private static string? SingleField(IEnumerable<string> values)
    {
        var fields = values.SelectMany(v => v.Split(',')).ToList();
        if (fields.Count != 1) return null;

        var field = fields[0];
        if (field.StartsWith("type=", StringComparison.OrdinalIgnoreCase)) return null;
        return NonEmpty(field.StartsWith("label=", StringComparison.OrdinalIgnoreCase) ? field["label=".Length..] : field);
    }

    private static string? NonEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private static bool IsFlag(string token) => token.Length > 1 && token[0] == '-' && token != "--";

    /// <summary>
    /// Reads the flag at <paramref name="i"/> and advances past it and any value it
    /// takes. Returns false for a flag the table does not know or a value that is
    /// missing; <paramref name="i"/> still advances past the flag token itself.
    /// </summary>
    private static bool TryReadFlag(IReadOnlyList<string> args, ref int i, IReadOnlyList<Flag> table, List<(string Name, string? Value)> into)
    {
        var token = args[i++];

        if (token.StartsWith("--", StringComparison.Ordinal))
        {
            var equals = token.IndexOf('=');
            var name = equals < 0 ? token[2..] : token[2..equals];
            var flag = table.FirstOrDefault(f => f.Long == name);
            if (flag is null) return false;

            if (equals >= 0)
            {
                into.Add((name, token[(equals + 1)..]));
                return true;
            }

            if (!flag.TakesValue)
            {
                into.Add((name, null));
                return true;
            }

            if (i >= args.Count) return false;
            into.Add((name, args[i++]));
            return true;
        }

        // A short cluster: switches until the first flag that takes a value, which
        // swallows the rest of the token, or the next token when nothing is left.
        for (var j = 1; j < token.Length; j++)
        {
            var flag = table.FirstOrDefault(f => f.Short == token[j]);
            if (flag is null) return false;

            var rest = token[(j + 1)..];
            if (rest.StartsWith('='))
            {
                into.Add((flag.Long, rest[1..]));
                return true;
            }

            if (!flag.TakesValue)
            {
                into.Add((flag.Long, null));
                continue;
            }

            if (rest.Length > 0)
            {
                into.Add((flag.Long, rest));
                return true;
            }

            if (i >= args.Count) return false;
            into.Add((flag.Long, args[i++]));
            return true;
        }

        return true;
    }
}
