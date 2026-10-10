using System.Globalization;
using OpWarden.Core;
using OpWarden.Core.Agent;
using OpWarden.Core.Rules;

namespace OpWarden.SessionAgent;

/// <summary>
/// What one read toast says: reads one caller made the same way within a few seconds of
/// each other, such as the two a tofu run makes back to back (REQ-RULE-39).
/// </summary>
internal sealed record ReadToast(CallerIdentity Caller, ReadSource Source, IReadOnlyList<SecretPath> Paths, DateTimeOffset? CacheExpires, DateTimeOffset LastReadAt)
{
    /// <summary>
    /// How far apart two reads may arrive and still share a toast.
    /// </summary>
    public static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(4);

    public static ReadToast Start(ReadAllowed read) => new(read.Caller, read.Source, [.. read.Paths.Distinct()], read.CacheExpires, read.At);

    /// <summary>
    /// This toast with <paramref name="read"/> added, or null when the read starts a toast
    /// of its own: another caller, another source, or too long after the last one.
    /// </summary>
    public ReadToast? Absorb(ReadAllowed read)
    {
        if (read.Caller != Caller || read.Source != Source || read.At - LastReadAt > BurstWindow) return null;
        DateTimeOffset? expires = CacheExpires is { } mine && read.CacheExpires is { } theirs ? (mine < theirs ? mine : theirs) : CacheExpires ?? read.CacheExpires;
        return this with { Paths = [.. Paths.Concat(read.Paths).Distinct()], CacheExpires = expires, LastReadAt = read.At };
    }

    public string Title => Paths.Count == 1 ? $"{Caller.Name} read a secret" : $"{Caller.Name} read {Paths.Count} secrets";

    /// <summary>
    /// One line per secret, set apart from the prose the way the prompt shows them.
    /// </summary>
    public IReadOnlyList<string> Lines => [.. Paths.Select(Describe)];

    public string Footer(DateTimeOffset now) => Source switch
    {
        ReadSource.Cache when CacheExpires is { } expires => $"From the cache, kept until {expires.ToLocalTime().ToString("HH:mm", CultureInfo.CurrentCulture)} ({Remaining(expires - now)} left)",
        ReadSource.Cache => "From the cache",
        _ => "Allowed by a rule. If Windows Hello asks next, this is what it is for.",
    };

    public static string Describe(SecretPath path) => $"{path.Vault ?? "?"} / {path.Item ?? "?"} / {path.Key ?? "?"}";

    private static string Remaining(TimeSpan left) =>
        left.TotalMinutes < 1 ? "under a minute"
        : left.TotalHours < 1 ? $"{(int)left.TotalMinutes} min"
        : $"{(int)left.TotalHours} h {left.Minutes} min";
}
