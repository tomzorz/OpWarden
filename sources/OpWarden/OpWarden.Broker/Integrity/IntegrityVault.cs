using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace OpWarden.Broker.Integrity;

/// <summary>
/// Raised when stored or in-memory state fails its integrity check.
/// </summary>
public sealed class TamperedException(string message) : Exception(message);

/// <summary>
/// The broker's integrity key and the generation counter of each sealed file, kept in one
/// file encrypted with DPAPI for the account the broker runs as.
/// </summary>
/// <remarks>
/// Under the service account (spec section 8) nothing running as the interactive user
/// can decrypt the vault, so a file edit cannot be re-sealed. In the console broker the
/// vault belongs to the user who started it, and the seal only stops casual edits.
///
/// The generations defeat rollback: a sealed file carries the generation it was written
/// at, and the vault remembers the latest, so an older copy with a valid seal is still
/// refused.
/// </remarks>
public sealed partial class IntegrityVault
{
    private const int KeyLength = 32;
    private readonly string _path;
    private readonly byte[] _key;
    private readonly Dictionary<string, long> _generations;
    private readonly Lock _lock = new();

    private IntegrityVault(string path, byte[] key, Dictionary<string, long> generations) => (_path, _key, _generations) = (path, key, generations);

    /// <summary>
    /// True when the vault was created by this call: there was no earlier state to protect.
    /// </summary>
    public bool IsNew { get; private init; }

    /// <summary>
    /// Opens the vault, or creates one with a fresh random key when the file does not exist.
    /// </summary>
    public static IntegrityVault Open(string path)
    {
        if (!File.Exists(path))
        {
            var created = new IntegrityVault(path, RandomNumberGenerator.GetBytes(KeyLength), []) { IsNew = true };
            created.Save();
            return created;
        }

        byte[] plain;
        try
        {
            plain = Unprotect(File.ReadAllBytes(path));
        }
        catch (Win32Exception e)
        {
            throw new TamperedException($"The integrity vault {path} cannot be decrypted ({e.Message}); it was altered, or belongs to another account.");
        }

        try
        {
            var key = plain[..KeyLength];
            var generations = new Dictionary<string, long>(StringComparer.Ordinal);
            var offset = KeyLength;
            while (offset < plain.Length)
            {
                var nameLength = plain[offset++];
                var name = System.Text.Encoding.UTF8.GetString(plain, offset, nameLength);
                offset += nameLength;
                generations[name] = BinaryPrimitives.ReadInt64LittleEndian(plain.AsSpan(offset, 8));
                offset += 8;
            }

            return new IntegrityVault(path, key, generations);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// <summary>
    /// The generation a sealed file was last written at, or 0 when it never was.
    /// </summary>
    public long Generation(string name)
    {
        lock (_lock) return _generations.GetValueOrDefault(name);
    }

    /// <summary>
    /// Records that a sealed file now stands at <paramref name="generation"/>.
    /// </summary>
    public void SetGeneration(string name, long generation)
    {
        lock (_lock)
        {
            _generations[name] = generation;
            Save();
        }
    }

    /// <summary>
    /// The HMAC of <paramref name="data"/> under the vault key.
    /// </summary>
    public byte[] Mac(ReadOnlySpan<byte> data) => HMACSHA256.HashData(_key, data);

    private void Save()
    {
        using var buffer = new MemoryStream();
        buffer.Write(_key);
        Span<byte> number = stackalloc byte[8];
        foreach (var (name, generation) in _generations)
        {
            var nameBytes = System.Text.Encoding.UTF8.GetBytes(name);
            buffer.WriteByte((byte)nameBytes.Length);
            buffer.Write(nameBytes);
            BinaryPrimitives.WriteInt64LittleEndian(number, generation);
            buffer.Write(number);
        }

        var plain = buffer.ToArray();
        try
        {
            Storage.AtomicFile.Write(_path, Protect(plain));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    // ---- DPAPI, without the ProtectedData package ------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int Length;
        public nint Data;
    }

    private const int CryptProtectUiForbidden = 0x1;

    private static unsafe byte[] Protect(byte[] plain) => Transform(plain, protect: true);

    private static unsafe byte[] Unprotect(byte[] cipher) => Transform(cipher, protect: false);

    private static unsafe byte[] Transform(byte[] input, bool protect)
    {
        fixed (byte* data = input)
        {
            var source = new DataBlob { Length = input.Length, Data = (nint)data };
            DataBlob result;
            var ok = protect
                ? CryptProtectData(&source, null, null, null, null, CryptProtectUiForbidden, &result)
                : CryptUnprotectData(&source, null, null, null, null, CryptProtectUiForbidden, &result);
            if (!ok) throw new Win32Exception(Marshal.GetLastPInvokeError());

            try
            {
                return new Span<byte>((void*)result.Data, result.Length).ToArray();
            }
            finally
            {
                new Span<byte>((void*)result.Data, result.Length).Clear();
                LocalFree(result.Data);
            }
        }
    }

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CryptProtectData(DataBlob* input, char* description, DataBlob* entropy, void* reserved, void* prompt, int flags, DataBlob* output);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool CryptUnprotectData(DataBlob* input, char** description, DataBlob* entropy, void* reserved, void* prompt, int flags, DataBlob* output);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);
}
