using System.Security.Cryptography;
using System.Text;
using OpWarden.Broker.Storage;
using OpWarden.Core.Rules;

namespace OpWarden.Broker.Cache;

/// <summary>
/// What a cache entry answers for: one caller identity (REQ-CACHE-5) running one exact
/// <c>op read</c> invocation.
/// </summary>
public sealed record CacheKey(string Caller, string Invocation)
{
    public static CacheKey For(CallerIdentity caller, IReadOnlyList<string> arguments) => new(caller.Name, string.Join('\0', arguments));
}

/// <summary>
/// The broker's cache of granted <c>op read</c> output (spec section 9): in process memory
/// only (REQ-CACHE-1), encrypted and locked (<see cref="ProtectedBuffer"/>), deleted when its
/// TTL elapses (REQ-CACHE-6), and flushable at once (REQ-CACHE-7, REQ-CACHE-8).
/// </summary>
/// <remarks>
/// Each entry carries a seal under the per-process memory key over its key, its expiry
/// and its plaintext, checked on every hit. An entry that fails the check is dropped and
/// reported instead of served: changing a cached value or stretching its expiry from
/// outside the broker earns a fresh op CLI run, not a forged answer (REQ-INT-7).
/// </remarks>
public sealed class SecretCache : IDisposable
{
    // ceiling: a fixed entry cap with oldest-expiry eviction; a byte budget would bound
    // memory more precisely if large secrets become common.
    private const int MaxEntries = 256;

    private readonly Func<DateTimeOffset> _now;
    private readonly Action<string> _tampered;
    private readonly Dictionary<CacheKey, Entry> _entries = [];
    private readonly Lock _lock = new();
    private readonly Timer _sweeper;

    public SecretCache(Action<string> tampered, Func<DateTimeOffset>? now = null)
    {
        _tampered = tampered;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _sweeper = new Timer(_ => Sweep(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
    }

    public int Count
    {
        get
        {
            lock (_lock) return _entries.Count;
        }
    }

    public static TimeSpan Duration(CacheTtl ttl) => ttl switch
    {
        CacheTtl.FifteenMinutes => TimeSpan.FromMinutes(15),
        CacheTtl.OneHour => TimeSpan.FromHours(1),
        CacheTtl.EightHours => TimeSpan.FromHours(8),
        _ => throw new ArgumentOutOfRangeException(nameof(ttl), ttl, null),
    };

    public void Put(CacheKey key, ReadOnlySpan<byte> output, CacheTtl ttl)
    {
        var expires = _now() + Duration(ttl);
        var entry = new Entry(ProtectedBuffer.Create(output), expires, Seal(key, expires, output));
        lock (_lock)
        {
            if (_entries.Remove(key, out var replaced)) replaced.Buffer.Dispose();
            if (_entries.Count >= MaxEntries) Evict(_entries.MinBy(e => e.Value.Expires).Key);
            _entries[key] = entry;
        }
    }

    /// <summary>
    /// The cached output, or null on a miss, an expired entry, or one that failed its seal.
    /// </summary>
    public byte[]? TryGet(CacheKey key)
    {
        lock (_lock)
        {
            if (!_entries.TryGetValue(key, out var entry)) return null;
            if (entry.Expires <= _now())
            {
                Evict(key);
                return null;
            }

            var plain = entry.Buffer.Reveal();
            if (CryptographicOperations.FixedTimeEquals(entry.Seal, Seal(key, entry.Expires, plain))) return plain;

            CryptographicOperations.ZeroMemory(plain);
            Evict(key);
            _tampered($"A cached value for {key.Caller} no longer matched its seal: something outside OpWarden changed the broker's memory. The entry was dropped, and the next call runs the op CLI.");
            return null;
        }
    }

    /// <summary>
    /// Deletes every entry.
    /// </summary>
    public int Flush()
    {
        lock (_lock)
        {
            var count = _entries.Count;
            foreach (var entry in _entries.Values) entry.Buffer.Dispose();
            _entries.Clear();
            return count;
        }
    }

    /// <summary>
    /// Deletes every expired entry.
    /// </summary>
    public void Sweep()
    {
        lock (_lock)
        {
            var now = _now();
            foreach (var key in _entries.Where(e => e.Value.Expires <= now).Select(e => e.Key).ToList()) Evict(key);
        }
    }

    /// <summary>
    /// The entry behind a key, for tests that play the attacker with the broker's memory.
    /// </summary>
    internal ProtectedBuffer? BufferFor(CacheKey key)
    {
        lock (_lock) return _entries.TryGetValue(key, out var entry) ? entry.Buffer : null;
    }

    public void Dispose()
    {
        _sweeper.Dispose();
        Flush();
    }

    private void Evict(CacheKey key)
    {
        if (_entries.Remove(key, out var entry)) entry.Buffer.Dispose();
    }

    private static byte[] Seal(CacheKey key, DateTimeOffset expires, ReadOnlySpan<byte> plain)
    {
        var header = Encoding.UTF8.GetBytes($"{key.Caller}\n{key.Invocation}\n{expires.UtcTicks}\n");
        var data = new byte[header.Length + plain.Length];
        header.CopyTo(data, 0);
        plain.CopyTo(data.AsSpan(header.Length));
        try
        {
            return MemorySeal.Of(data);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    private sealed record Entry(ProtectedBuffer Buffer, DateTimeOffset Expires, byte[] Seal);
}
