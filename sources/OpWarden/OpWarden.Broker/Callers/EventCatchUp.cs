using System.Diagnostics;

namespace OpWarden.Broker.Callers;

/// <summary>
/// Walks again while the walk is waiting for process events, flushing the event session
/// between attempts, for a bounded time (REQ-CALL-26).
/// </summary>
/// <remarks>
/// ETW hands events to the consumer in batches, up to a second apart. A shim that an
/// MSYS2 shell started a few milliseconds ago has ancestors whose starts and exits are
/// still in those buffers. Walking ahead of them is how an earlier process with the same
/// ID got taken for a parent; waiting for them costs a flush and a few milliseconds, and
/// only for the walks that need it.
/// </remarks>
internal static class EventCatchUp
{
    public static readonly TimeSpan DefaultBudget = TimeSpan.FromSeconds(2);

    // ceiling: polls; a signal from the event handler when the awaited entry lands would
    // save the sleeps, at the cost of a wait list the handler must touch (REQ-CALL-3).
    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(10);

    /// <param name="walk">One walk of the ancestry.</param>
    /// <param name="flush">Pushes buffered events to the map; null when no event session runs, so waiting can never help.</param>
    public static async ValueTask<CallerResolution> ResolveAsync(Func<CallerResolution> walk, Action? flush, TimeSpan? budget = null)
    {
        var resolution = walk();
        if (!resolution.AwaitsEvents) return resolution;
        if (flush is null) return resolution.Final("no provable parent");

        var deadline = Stopwatch.GetTimestamp() + (long)((budget ?? DefaultBudget).TotalSeconds * Stopwatch.Frequency);
        do
        {
            flush();
            await Task.Delay(Poll).ConfigureAwait(false);
            resolution = walk();
        }
        while (resolution.AwaitsEvents && Stopwatch.GetTimestamp() < deadline);

        return resolution.Final("process events did not arrive in time");
    }
}
