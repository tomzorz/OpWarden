using System.ComponentModel;
using System.Runtime.InteropServices;

namespace OpWarden.Broker.Cache;

/// <summary>
/// One cached secret in native memory: outside the GC, so it never moves and leaves no
/// copies behind; locked against paging (REQ-CACHE-2); and encrypted in place with
/// <c>CryptProtectMemory</c>, so a scan of broker memory finds ciphertext, not the secret.
/// </summary>
internal sealed unsafe partial class ProtectedBuffer : IDisposable
{
    // CRYPTPROTECTMEMORY_BLOCK_SIZE: the encrypted region must be a multiple of it.
    private const int BlockSize = 16;
    private const uint SameProcess = 0;

    private byte* _data;
    private readonly nuint _capacity;

    private ProtectedBuffer(byte* data, nuint capacity, int length, bool locked)
    {
        _data = data;
        _capacity = capacity;
        Length = length;
        IsLocked = locked;
    }

    public int Length { get; }

    /// <summary>
    /// False when <c>VirtualLock</c> refused, typically over the working-set quota. The
    /// value is still encrypted; it can reach the page file only as ciphertext.
    /// </summary>
    public bool IsLocked { get; }

    public static ProtectedBuffer Create(ReadOnlySpan<byte> plain)
    {
        var capacity = (nuint)Math.Max(BlockSize, (plain.Length + BlockSize - 1) / BlockSize * BlockSize);
        var data = (byte*)NativeMemory.AllocZeroed(capacity);
        var locked = VirtualLock(data, capacity);
        plain.CopyTo(new Span<byte>(data, plain.Length));
        if (!CryptProtectMemory(data, (uint)capacity, SameProcess))
        {
            var error = Marshal.GetLastPInvokeError();
            Release(data, capacity, locked);
            throw new Win32Exception(error, "CryptProtectMemory failed for a cache entry.");
        }

        return new ProtectedBuffer(data, capacity, plain.Length, locked);
    }

    /// <summary>
    /// Decrypts a copy and returns the plaintext. The buffer itself stays encrypted.
    /// </summary>
    public byte[] Reveal()
    {
        ObjectDisposedException.ThrowIf(_data is null, this);
        var scratch = (byte*)NativeMemory.Alloc(_capacity);
        try
        {
            new Span<byte>(_data, (int)_capacity).CopyTo(new Span<byte>(scratch, (int)_capacity));
            if (!CryptUnprotectMemory(scratch, (uint)_capacity, SameProcess)) throw new Win32Exception(Marshal.GetLastPInvokeError(), "CryptUnprotectMemory failed for a cache entry.");
            return new Span<byte>(scratch, Length).ToArray();
        }
        finally
        {
            new Span<byte>(scratch, (int)_capacity).Clear();
            NativeMemory.Free(scratch);
        }
    }

    /// <summary>
    /// The encrypted bytes, for tests that check no plaintext sits in memory.
    /// </summary>
    internal ReadOnlySpan<byte> Ciphertext => new(_data, (int)_capacity);

    public void Dispose()
    {
        if (_data is null) return;
        Release(_data, _capacity, IsLocked);
        _data = null;
    }

    private static void Release(byte* data, nuint capacity, bool locked)
    {
        new Span<byte>(data, (int)capacity).Clear();
        if (locked) VirtualUnlock(data, capacity);
        NativeMemory.Free(data);
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualLock(void* address, nuint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualUnlock(void* address, nuint size);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptProtectMemory(void* data, uint size, uint flags);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptUnprotectMemory(void* data, uint size, uint flags);
}
