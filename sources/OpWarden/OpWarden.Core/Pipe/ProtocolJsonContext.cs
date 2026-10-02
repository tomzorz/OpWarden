using System.Text.Json.Serialization;

namespace OpWarden.Core.Pipe;

// Source-generated, because reflection-based serialization does not survive NativeAOT.
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true)]
[JsonSerializable(typeof(ShimRequest))]
[JsonSerializable(typeof(VerdictResponse))]
[JsonSerializable(typeof(ReadCapture))]
internal sealed partial class ProtocolJsonContext : JsonSerializerContext;
