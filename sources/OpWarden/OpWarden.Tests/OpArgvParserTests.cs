using OpWarden.Core;
using OpWarden.Core.CommandLine;

namespace OpWarden.Tests;

public sealed class OpArgvParserTests
{
    // Arguments are written '|'-separated so each case stays on one line.
    public static TheoryData<string, OpAction, string?, string?, string?, string?> Classifications => new()
    {
        // read (REQ-CLAS-2) and reference parsing (REQ-CLAS-10)
        { "read|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|op://v/i/s/f?attribute=otp", OpAction.Read, "read", "v", "i", "s/f" },
        { "read|op://My Vault/My Item/password", OpAction.Read, "read", "My Vault", "My Item", "password" },
        { "read|-n|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|-o|out.txt|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|-oout.txt|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|--out-file=out.txt|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|-fno|out.txt|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|op://v/i/f|--force", OpAction.Read, "read", "v", "i", "f" },
        { "read|--|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "--account|acme|read|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "--format=json|read|op://v/i/f", OpAction.Read, "read", "v", "i", "f" },
        { "read|op://v/i", OpAction.Read, "read", null, null, null },
        { "read|op://$ENV/i/f", OpAction.Read, "read", null, null, null },
        { "read|op://v/i/f|op://v/i/g", OpAction.Read, "read", null, null, null },
        { "read|op://v/i/f#x", OpAction.Read, "read", null, null, null },
        { "read|--bogus|op://v/i/f", OpAction.Read, "read", null, null, null },
        { "read|-o", OpAction.Read, "read", null, null, null },

        // item get and friends
        { "item|get|Item|--vault|V|--fields|label=password", OpAction.Read, "item get", "V", "Item", "password" },
        { "item|get|--vault|V|Item|--fields=password", OpAction.Read, "item get", "V", "Item", "password" },
        { "item|get|Item|--vault=V|--fields|username,password", OpAction.Read, "item get", "V", "Item", null },
        { "item|get|Item|--fields|username|--fields|password", OpAction.Read, "item get", null, "Item", null },
        { "item|get|Item|--fields|type=concealed", OpAction.Read, "item get", null, "Item", null },
        { "item|get|Item", OpAction.Read, "item get", null, "Item", null },
        { "item|get|-|--vault|V", OpAction.Read, "item get", "V", null, null },
        { "item|get|https://share.1password.com/s#abc", OpAction.Read, "item get", null, null, null },
        { "item|get|A|B", OpAction.Read, "item get", null, null, null },
        { "item|get|Item|--vault=", OpAction.Read, "item get", null, "Item", null },
        { "item|get|Item|--reveal|--otp", OpAction.Read, "item get", null, "Item", null },
        { "item|get|Item|--unknown-flag|V", OpAction.Read, "item get", null, null, null },
        { "item|list|--vault|V", OpAction.Read, "item list", "V", null, null },
        { "item|ls|--vault|V|--long", OpAction.Read, "item list", "V", null, null },
        { "document|get|Doc|--vault|V|-o|file.pdf", OpAction.Read, "document get", "V", "Doc", null },
        { "user|get|--me", OpAction.Read, "user get", null, null, null },

        // write, delete (REQ-CLAS-3, REQ-CLAS-4)
        { "item|create|--title|T|--vault|V|password=hunter2", OpAction.Write, "item create", "V", "T", null },
        { "item|create|--generate-password=20,letters|--title=T", OpAction.Write, "item create", null, "T", null },
        { "item|edit|Item|password=x|--vault|V", OpAction.Write, "item edit", "V", "Item", null },
        { "document|create|file.pdf|--title|Doc|--vault|V", OpAction.Write, "document create", "V", "Doc", null },
        { "document|edit|Doc|file.pdf|--vault|V", OpAction.Write, "document edit", "V", "Doc", null },
        { "item|delete|Item|--vault|V", OpAction.Delete, "item delete", "V", "Item", null },
        { "item|rm|Item|--archive", OpAction.Delete, "item delete", null, "Item", null },
        { "document|remove|Doc", OpAction.Delete, "document delete", null, "Doc", null },
        { "vault|delete|V", OpAction.Delete, "vault delete", "V", null, null },
        { "vault|rm|-", OpAction.Delete, "vault delete", null, null, null },

        // manage (REQ-CLAS-5)
        { "vault|list", OpAction.Manage, "vault list", null, null, null },
        { "vault|create|New", OpAction.Manage, "vault create", null, null, null },
        { "user|list", OpAction.Manage, "user list", null, null, null },
        { "account|list", OpAction.Manage, "account list", null, null, null },
        { "group|create|g", OpAction.Manage, "group create", null, null, null },

        // run (REQ-CLAS-6) and meta (REQ-CLAS-7)
        { "run|--env-file|.env|--|cmd", OpAction.Run, "run", null, null, null },
        { "inject|-i|tpl", OpAction.Run, "inject", null, null, null },
        { "--version", OpAction.Meta, "--version", null, null, null },
        { "-v", OpAction.Meta, "--version", null, null, null },
        { "signin", OpAction.Meta, "signin", null, null, null },
        { "signout|--all", OpAction.Meta, "signout", null, null, null },
        { "--format|json|whoami", OpAction.Meta, "whoami", null, null, null },

        // unknown (REQ-CLAS-8)
        { "", OpAction.Unknown, null, null, null, null },
        { "item", OpAction.Unknown, "item", null, null, null },
        { "item|move|Item", OpAction.Unknown, "item move", null, null, null },
        { "item|share|Item", OpAction.Unknown, "item share", null, null, null },
        { "document|list", OpAction.Unknown, "document list", null, null, null },
        { "completion|bash", OpAction.Unknown, null, null, null, null },
        { "connect|server|list", OpAction.Unknown, null, null, null, null },
        { "--help", OpAction.Unknown, null, null, null, null },
        { "--", OpAction.Unknown, null, null, null, null },
        { "frobnicate", OpAction.Unknown, null, null, null, null },
        { "READ|op://v/i/f", OpAction.Unknown, null, null, null, null },

        // A non-global flag before the command makes everything unknown: cobra would
        // skip it by guessing whether it takes a value, and here `get` is that value.
        { "--vault|get|item|get|Item", OpAction.Unknown, null, null, null, null },
        { "-o|x|read|op://v/i/f", OpAction.Unknown, null, null, null, null },
    };

    [Theory]
    [MemberData(nameof(Classifications))]
    public void Classifies_and_reads_the_secret_path(string argv, OpAction action, string? command, string? vault, string? item, string? key)
    {
        var parsed = OpArgvParser.Parse(Split(argv));

        Assert.Equal(action, parsed.Action);
        Assert.Equal(command, parsed.Command);
        Assert.Equal(new SecretPath(vault, item, key), parsed.Path);
    }

    [Theory]
    [InlineData("read|op://v/i/f", false)]
    [InlineData("read|op://v/i", true)]
    [InlineData("read|--bogus|op://v/i/f", true)]
    [InlineData("run|--env-file", true)]
    [InlineData("item|get|Item", false)]
    public void Marks_references_unknown_when_the_arguments_cannot_establish_them(string argv, bool unknown)
    {
        Assert.Equal(unknown, OpArgvParser.Parse(Split(argv)).ReferencesUnknown);
    }

    [Fact]
    public void Read_reports_its_reference()
    {
        var parsed = OpArgvParser.Parse(["read", "op://v/i/f"]);

        Assert.True(parsed.IsOpRead);
        Assert.Equal([new SecretPath("v", "i", "f")], parsed.ArgumentReferences);
    }

    [Fact]
    public void Item_get_is_read_but_not_op_read()
    {
        Assert.False(OpArgvParser.Parse(["item", "get", "Item"]).IsOpRead);
    }

    [Fact]
    public void Run_collects_env_files_in_order_and_stops_at_the_double_dash()
    {
        var parsed = OpArgvParser.Parse(["run", "--env-file=a", "--env-file", "b", "--", "cmd", "--env-file", "c"]);

        Assert.Equal(["a", "b"], parsed.EnvFiles);
    }

    [Fact]
    public void Inject_without_in_file_reads_the_template_from_stdin()
    {
        Assert.True(OpArgvParser.Parse(["inject", "-o", "out"]).TemplateFromStdin);
        Assert.False(OpArgvParser.Parse(["inject", "-i", "tpl"]).TemplateFromStdin);
        Assert.Equal("tpl", OpArgvParser.Parse(["inject", "--in-file=tpl"]).TemplateFile);
    }

    private static string[] Split(string argv) => argv.Length == 0 ? [] : argv.Split('|');
}
