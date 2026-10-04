using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace OpWarden.Broker.Callers;

/// <summary>
/// Decodes the payload of a <c>Microsoft-Windows-Kernel-Process</c> ProcessStart event
/// (event 1) by its version.
/// </summary>
/// <remarks>
/// The layouts come from the provider's own manifest (<c>TdhGetManifestEventInformation</c>,
/// Windows 10 19045), not from memory:
/// <code>
///   v0     ProcessID u32 · CreateTime u64 · ParentProcessID u32 · SessionID u32 · ImageName
///   v1, v2 ProcessID u32 · CreateTime u64 · ParentProcessID u32 · SessionID u32 · Flags u32
///          · ImageName · (v2: ImageChecksum, TimeDateStamp, PackageFullName, PackageRelativeAppId)
///   v3     ProcessID u32 · ProcessSequenceNumber u64 · CreateTime u64 · ParentProcessID u32
///          · ParentProcessSequenceNumber u64 · SessionID u32 · Flags u32
///          · ProcessTokenElevationType u32 · ProcessTokenIsElevated u32 · MandatoryLabel SID
///          · ImageName · ImageChecksum, TimeDateStamp, PackageFullName, PackageRelativeAppId
/// </code>
/// ImageName is a NUL-terminated UTF-16 NT device path. The SID describes its own length:
/// 8 bytes plus 4 per sub-authority, whose count is its second byte. An unknown version
/// decodes to nothing, and the process stays unresolvable rather than misread.
/// </remarks>
public static class ProcessStartDecoder
{
    public const ushort EventId = 1;

    public static readonly Guid Provider = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");

    public static ProcessEntry? Decode(byte version, ReadOnlySpan<byte> payload)
    {
        try
        {
            return version switch
            {
                0 => Entry(payload, processId: 0, createTime: 4, parentId: 12, session: 16, image: 20),
                1 or 2 => Entry(payload, processId: 0, createTime: 4, parentId: 12, session: 16, image: 24),
                3 => Entry(payload, processId: 0, createTime: 12, parentId: 20, session: 32, image: 48 + SidLength(payload[48..])),
                _ => null,
            };
        }
        catch (ArgumentOutOfRangeException)
        {
            // A payload shorter than its version promises.
            return null;
        }
    }

    private static ProcessEntry? Entry(ReadOnlySpan<byte> payload, int processId, int createTime, int parentId, int session, int image)
    {
        var name = MemoryMarshal.Cast<byte, char>(payload[image..]);
        var end = name.IndexOf('\0');
        if (end < 0) return null;

        return new ProcessEntry(
            BinaryPrimitives.ReadInt32LittleEndian(payload[processId..]),
            BinaryPrimitives.ReadInt32LittleEndian(payload[parentId..]),
            BinaryPrimitives.ReadInt64LittleEndian(payload[createTime..]),
            DevicePaths.ToDrivePath(new string(name[..end])),
            BinaryPrimitives.ReadInt32LittleEndian(payload[session..]));
    }

    private static int SidLength(ReadOnlySpan<byte> sid)
    {
        // Revision 1 is the only SID revision Windows has.
        if (sid[0] != 1) throw new ArgumentOutOfRangeException(nameof(sid), sid[0], "Not a SID.");
        return 8 + 4 * sid[1];
    }
}
