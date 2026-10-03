using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace OpWarden.Core.Pipe;

/// <summary>
/// One message per frame: a 4-byte little-endian length, then that many bytes of
/// UTF-8 JSON. Shared by the shim and session-agent conversations.
/// </summary>
internal static class Framing
{
    public static async Task WriteAsync<T>(Stream stream, T message, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, typeInfo);
        if (payload.Length > PipeProtocol.MaxFrameBytes) throw new InvalidDataException($"OpWarden pipe frame of {payload.Length} bytes exceeds the {PipeProtocol.MaxFrameBytes}-byte limit ({typeof(T).Name}).");

        var frame = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, payload.Length);
        payload.CopyTo(frame, 4);
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<T?> ReadAsync<T>(Stream stream, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
        where T : class
    {
        var header = new byte[4];
        var headerRead = await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (headerRead == 0) return null;
        if (headerRead < header.Length) throw new EndOfStreamException($"OpWarden pipe closed inside a frame header ({headerRead} of 4 bytes, {typeof(T).Name}).");

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is < 0 or > PipeProtocol.MaxFrameBytes) throw new InvalidDataException($"OpWarden pipe frame announces {length} bytes, outside 0..{PipeProtocol.MaxFrameBytes} ({typeof(T).Name}).");

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize(payload, typeInfo)
               ?? throw new InvalidDataException($"OpWarden pipe frame decoded to null ({typeof(T).Name}).");
    }
}
