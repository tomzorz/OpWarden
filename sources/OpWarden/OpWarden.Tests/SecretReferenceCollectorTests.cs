using OpWarden.Core;
using OpWarden.Core.CommandLine;

namespace OpWarden.Tests;

public sealed class SecretReferenceCollectorTests : IDisposable
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("opwarden-tests-");

    public void Dispose() => _directory.Delete(recursive: true);

    [Fact]
    public void Run_collects_references_from_the_environment()
    {
        var collected = Collect(["run", "--", "cmd"], new() { ["DB"] = "op://v/db/password", ["PATH"] = @"C:\bin" });

        Assert.False(collected.Unknown);
        Assert.Equal([new SecretPath("v", "db", "password")], collected.References);
    }

    [Fact]
    public void Run_collects_references_from_env_files()
    {
        var envFile = Write(".env", """
            # database
            DB_USER=op://v/db/username
            export DB_PASSWORD = "op://v/db/password"
            API='op://v/api/token'
            PLAIN=hello

            """);

        var collected = Collect(["run", "--env-file", envFile, "--", "cmd"], []);

        Assert.False(collected.Unknown);
        Assert.Equal(
            [new SecretPath("v", "db", "username"), new SecretPath("v", "db", "password"), new SecretPath("v", "api", "token")],
            collected.References);
    }

    [Fact]
    public void An_env_file_overrides_the_environment_and_a_later_file_an_earlier_one()
    {
        var first = Write("first.env", "A=op://v/first/a\nB=op://v/first/b\n");
        var second = Write("second.env", "B=op://v/second/b\n");

        var collected = Collect(["run", "--env-file", first, "--env-file", second, "--", "cmd"], new() { ["A"] = "op://v/shell/a", ["C"] = "op://v/shell/c" });

        Assert.Equal(
            new[] { new SecretPath("v", "first", "a"), new SecretPath("v", "second", "b"), new SecretPath("v", "shell", "c") }.OrderBy(p => p.Item),
            collected.References.OrderBy(p => p.Item));
    }

    [Fact]
    public void Env_file_references_expand_variables()
    {
        var envFile = Write(".env", "DB = op://$APP_ENV/db/password\n");

        var collected = Collect(["run", "--env-file", envFile, "--", "cmd"], new() { ["APP_ENV"] = "prod" });

        Assert.Equal([new SecretPath("prod", "db", "password")], collected.References);
    }

    [Theory]
    [InlineData("DB=op://$MISSING/db/password")]
    [InlineData("URL=postgres://u:op://v/db/pw@host")]
    [InlineData("DB=op://v/db")]
    [InlineData("DB=op://v/db/password # comment")]
    public void Run_references_it_cannot_pin_down_are_unknown(string line)
    {
        var envFile = Write(".env", line + "\n");

        Assert.True(Collect(["run", "--env-file", envFile, "--", "cmd"], []).Unknown);
    }

    [Fact]
    public void An_unreadable_env_file_makes_references_unknown()
    {
        var collected = Collect(["run", "--env-file", Path.Combine(_directory.FullName, "missing.env"), "--", "cmd"], new() { ["DB"] = "op://v/db/password" });

        Assert.True(collected.Unknown);
    }

    [Fact]
    public void Inject_collects_braced_and_bare_references()
    {
        var template = Write("config.tpl", """
            db_password: {{ op://v/db/password }}
            db_url: postgres://{{op://v/db/user}}:{{ op://v/db/pw }}@host
            api_token: op://v/api/token
            name: {{ op://My Vault/My Item/field }}
            """);

        var collected = Collect(["inject", "-i", template], []);

        Assert.False(collected.Unknown);
        Assert.Equal(
            new[] { new SecretPath("v", "db", "password"), new SecretPath("v", "db", "user"), new SecretPath("v", "db", "pw"), new SecretPath("v", "api", "token"), new SecretPath("My Vault", "My Item", "field") }.OrderBy(p => p.Key),
            collected.References.OrderBy(p => p.Key));
    }

    [Fact]
    public void A_bare_template_reference_with_no_visible_end_is_unknown()
    {
        var template = Write("config.tpl", "token: op://v/api/token more words\n");

        Assert.True(Collect(["inject", "-i", template], []).Unknown);
    }

    [Fact]
    public void A_bare_reference_ended_by_a_comment_is_fine()
    {
        var template = Write("config.tpl", "token: op://v/api/token # the api token\n");

        var collected = Collect(["inject", "-i", template], []);

        Assert.False(collected.Unknown);
        Assert.Equal([new SecretPath("v", "api", "token")], collected.References);
    }

    [Fact]
    public void Inject_from_stdin_has_unknown_references()
    {
        Assert.True(Collect(["inject"], []).Unknown);
    }

    [Fact]
    public void Read_passes_its_argument_reference_through()
    {
        var collected = Collect(["read", "op://v/i/f"], []);

        Assert.False(collected.Unknown);
        Assert.Equal([new SecretPath("v", "i", "f")], collected.References);
    }

    private static CollectedReferences Collect(string[] args, Dictionary<string, string> environment) =>
        SecretReferenceCollector.Collect(OpArgvParser.Parse(args), environment);

    private string Write(string name, string content)
    {
        var path = Path.Combine(_directory.FullName, name);
        File.WriteAllText(path, content);
        return path;
    }
}
