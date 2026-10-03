using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using OpWarden.Broker.Cache;
using OpWarden.Core.Rules;

namespace OpWarden.Tests;

public sealed class SecretCacheTests : IDisposable
{
    private static readonly CacheKey Key = CacheKey.For(CallerIdentity.Agent("claude-code"), ["read", "op://V/I/K"]);
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("correct horse battery staple\n");

    private readonly List<string> _alarms = [];
    private DateTimeOffset _now = new(2026, 10, 3, 12, 0, 0, TimeSpan.Zero);
    private readonly SecretCache _cache;

    public SecretCacheTests() => _cache = new SecretCache(_alarms.Add, () => _now);

    public void Dispose() => _cache.Dispose();

    [Fact]
    public void A_cached_value_comes_back_for_the_same_caller_and_invocation()
    {
        _cache.Put(Key, Secret, CacheTtl.OneHour);

        Assert.Equal(Secret, _cache.TryGet(Key));
        Assert.Null(_cache.TryGet(CacheKey.For(CallerIdentity.Agent("codex"), ["read", "op://V/I/K"])));
        Assert.Null(_cache.TryGet(CacheKey.For(CallerIdentity.Agent("claude-code"), ["read", "-n", "op://V/I/K"])));
    }

    [Fact]
    public void An_empty_value_is_a_value()
    {
        _cache.Put(Key, [], CacheTtl.FifteenMinutes);

        Assert.Equal([], Assert.IsType<byte[]>(_cache.TryGet(Key)));
    }

    [Theory]
    [InlineData(CacheTtl.FifteenMinutes, 14, true)]
    [InlineData(CacheTtl.FifteenMinutes, 15, false)]
    [InlineData(CacheTtl.EightHours, 479, true)]
    public void An_entry_lives_exactly_its_ttl(CacheTtl ttl, int minutesLater, bool present)
    {
        _cache.Put(Key, Secret, ttl);
        _now += TimeSpan.FromMinutes(minutesLater);

        Assert.Equal(present, _cache.TryGet(Key) is not null);
    }

    [Fact]
    public void The_sweep_deletes_expired_entries()
    {
        _cache.Put(Key, Secret, CacheTtl.FifteenMinutes);
        _now += TimeSpan.FromHours(1);

        _cache.Sweep();

        Assert.Equal(0, _cache.Count);
    }

    [Fact]
    public void A_flush_deletes_everything()
    {
        _cache.Put(Key, Secret, CacheTtl.OneHour);
        _cache.Put(CacheKey.For(CallerIdentity.InteractiveUser, ["read", "op://V/I/K"]), Secret, CacheTtl.OneHour);

        Assert.Equal(2, _cache.Flush());
        Assert.Null(_cache.TryGet(Key));
    }

    [Fact]
    public void The_value_sits_in_memory_encrypted()
    {
        _cache.Put(Key, Secret, CacheTtl.OneHour);

        var ciphertext = _cache.BufferFor(Key)!.Ciphertext.ToArray();

        Assert.Equal(-1, ciphertext.AsSpan().IndexOf(Secret.AsSpan(0, 8)));
    }

    [Fact]
    public void A_value_changed_in_memory_is_dropped_and_reported_instead_of_served()
    {
        _cache.Put(Key, Secret, CacheTtl.OneHour);

        // Play the attacker with the broker's memory: flip one byte of the stored value.
        ref var first = ref MemoryMarshal.GetReference(_cache.BufferFor(Key)!.Ciphertext);
        first ^= 0x01;

        Assert.Null(_cache.TryGet(Key));
        Assert.Single(_alarms);
        Assert.Equal(0, _cache.Count);
    }

    [Fact]
    public void An_expiry_stretched_in_memory_is_caught()
    {
        _cache.Put(Key, Secret, CacheTtl.FifteenMinutes);
        var entries = (System.Collections.IDictionary)typeof(SecretCache).GetField("_entries", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(_cache)!;
        var entry = entries[Key]!;
        var stretched = entry.GetType().GetMethod("<Clone>$")!.Invoke(entry, null)!;
        entry.GetType().GetProperty("Expires")!.SetValue(stretched, _now + TimeSpan.FromDays(30));
        entries[Key] = stretched;

        Assert.Null(_cache.TryGet(Key));
        Assert.Single(_alarms);
    }
}
