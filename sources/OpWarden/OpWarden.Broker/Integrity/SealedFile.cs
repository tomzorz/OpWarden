using System.Text;
using System.Text.Json;
using OpWarden.Broker.Storage;

namespace OpWarden.Broker.Integrity;

/// <summary>
/// A JSON file whose content carries a seal: an HMAC under the vault key over its name,
/// its generation and its exact content bytes.
/// </summary>
/// <remarks>
/// <code>
///   { "name": "rules", "generation": 7, "mac": "base64…", "content": { …as written… } }
/// </code>
/// The seal covers the content bytes exactly as written, so verifying needs no
/// canonical form: the reader takes the raw text of <c>content</c> and recomputes. The
/// file stays readable by a human (REQ-TRUST-2 lets the interactive user read it); an
/// edit by anything but the broker breaks the seal.
/// </remarks>
public static class SealedFile
{
    /// <summary>
    /// Writes the content sealed at the next generation. The file goes first and the
    /// vault second, so a crash between them leaves a file one generation ahead of the
    /// vault, which <see cref="Read"/> accepts.
    /// </summary>
    public static void Write(string path, string name, byte[] content, IntegrityVault vault)
    {
        var generation = vault.Generation(name) + 1;
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("name", name);
            writer.WriteNumber("generation", generation);
            writer.WriteBase64String("mac", Seal(vault, name, generation, content));
            writer.WritePropertyName("content");
            writer.WriteRawValue(content, skipInputValidation: false);
            writer.WriteEndObject();
        }

        AtomicFile.Write(path, buffer.ToArray());
        vault.SetGeneration(name, generation);
    }

    /// <summary>
    /// Reads and verifies the content, or returns null when the file was never written.
    /// Throws <see cref="TamperedException"/> for a broken seal, a rolled-back copy, or a
    /// file that vanished after the vault recorded it.
    /// </summary>
    public static byte[]? Read(string path, string name, IntegrityVault vault)
    {
        var expected = vault.Generation(name);
        if (!File.Exists(path))
        {
            return expected == 0 ? null : throw new TamperedException($"{path} is missing, but the broker wrote generation {expected} of it.");
        }

        long generation;
        byte[] mac;
        byte[] content;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllBytes(path));
            var root = document.RootElement;
            if (root.GetProperty("name").GetString() != name) throw new TamperedException($"{path} is sealed as another file.");
            generation = root.GetProperty("generation").GetInt64();
            mac = root.GetProperty("mac").GetBytesFromBase64();
            content = Encoding.UTF8.GetBytes(root.GetProperty("content").GetRawText());
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new TamperedException($"{path} is not a sealed OpWarden file ({e.Message}).");
        }

        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(mac, Seal(vault, name, generation, content)))
        {
            throw new TamperedException($"{path} was changed by something other than the OpWarden broker: its seal does not match.");
        }

        if (generation < expected) throw new TamperedException($"{path} is generation {generation}, older than generation {expected} the broker last wrote: an earlier copy was put back.");
        if (generation > expected + 1) throw new TamperedException($"{path} is generation {generation}, ahead of the {expected} the broker last wrote.");
        if (generation == expected + 1) vault.SetGeneration(name, generation);
        return content;
    }

    private static byte[] Seal(IntegrityVault vault, string name, long generation, byte[] content)
    {
        var header = Encoding.UTF8.GetBytes($"{name}\n{generation}\n");
        return vault.Mac([.. header, .. content]);
    }
}
