using System.Buffers.Binary;
using OpWarden.Core;
using OpWarden.Core.Pipe;

namespace OpWarden.Tests;

public sealed class PipeProtocolTests
{
    [Fact]
    public async Task Messages_round_trip()
    {
        var request = new ShimRequest(PipeProtocol.Version, ["read", "op://v/i/f"], "read", OpAction.Read, new SecretPath("v", "i", "f"), [new SecretPath("v", "i", "f")], false);
        var verdict = VerdictResponse.FromCache([1, 2, 3]);
        var capture = new ReadCapture(0, [0x68, 0x69], false);
        using var stream = new MemoryStream();

        await PipeProtocol.WriteAsync(stream, request, TestContext.Current.CancellationToken);
        await PipeProtocol.WriteAsync(stream, verdict, TestContext.Current.CancellationToken);
        await PipeProtocol.WriteAsync(stream, capture, TestContext.Current.CancellationToken);
        stream.Position = 0;

        var readRequest = await PipeProtocol.ReadRequestAsync(stream, TestContext.Current.CancellationToken);
        var readVerdict = await PipeProtocol.ReadVerdictAsync(stream, TestContext.Current.CancellationToken);
        var readCapture = await PipeProtocol.ReadCaptureAsync(stream, TestContext.Current.CancellationToken);

        Assert.NotNull(readRequest);
        Assert.Equal(request.Arguments, readRequest.Arguments);
        Assert.Equal(request.Path, readRequest.Path);
        Assert.Equal(request.SecretReferences, readRequest.SecretReferences);
        Assert.Equal(request with { Arguments = readRequest.Arguments, SecretReferences = readRequest.SecretReferences }, readRequest);
        Assert.Equal(verdict.Cached!.Bytes, readVerdict?.Cached?.Bytes);
        Assert.Equal(capture.Output, readCapture?.Output);
    }

    [Fact]
    public async Task A_run_verdict_round_trips_without_cached_output()
    {
        using var stream = new MemoryStream();
        await PipeProtocol.WriteAsync(stream, VerdictResponse.RunOp(@"C:\op\op.exe"), TestContext.Current.CancellationToken);
        stream.Position = 0;

        var verdict = await PipeProtocol.ReadVerdictAsync(stream, TestContext.Current.CancellationToken);

        Assert.Equal(new VerdictResponse(Verdict.Allow, @"C:\op\op.exe", null, null), verdict);
    }

    [Fact]
    public async Task Enums_travel_as_names()
    {
        using var stream = new MemoryStream();
        await PipeProtocol.WriteAsync(stream, VerdictResponse.Deny("no"), TestContext.Current.CancellationToken);

        var json = System.Text.Encoding.UTF8.GetString(stream.ToArray(), 4, (int)stream.Length - 4);

        Assert.Contains("\"verdict\":\"Deny\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_clean_end_of_stream_reads_as_null()
    {
        using var stream = new MemoryStream();

        Assert.Null(await PipeProtocol.ReadRequestAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_stream_that_ends_inside_a_frame_throws()
    {
        using var stream = new MemoryStream([5, 0]);

        await Assert.ThrowsAsync<EndOfStreamException>(() => PipeProtocol.ReadRequestAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task An_oversized_frame_is_refused_before_it_is_read()
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, PipeProtocol.MaxFrameBytes + 1);
        using var stream = new MemoryStream(header);

        await Assert.ThrowsAsync<InvalidDataException>(() => PipeProtocol.ReadRequestAsync(stream, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(OpAction.Read, Verdict.Allow, false, true)]
    [InlineData(OpAction.Read, Verdict.Allow, true, false)]
    [InlineData(OpAction.Read, Verdict.Deny, false, false)]
    [InlineData(OpAction.Run, Verdict.Allow, false, false)]
    [InlineData(OpAction.Meta, Verdict.Allow, false, false)]
    public void A_capture_is_owed_only_for_an_allowed_read_that_runs_the_op_cli(OpAction action, Verdict verdict, bool cached, bool expected)
    {
        var request = new ShimRequest(PipeProtocol.Version, [], null, action, SecretPath.Unknown, [], false);
        var response = new VerdictResponse(verdict, cached ? null : @"C:\op.exe", cached ? new CachedOutput([1]) : null, null);

        Assert.Equal(expected, PipeProtocol.ExpectsCapture(request, response));
    }
}
