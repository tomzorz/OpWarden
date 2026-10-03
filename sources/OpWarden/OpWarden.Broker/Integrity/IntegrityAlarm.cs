using OpWarden.Broker.Audit;
using OpWarden.Core.Agent;

namespace OpWarden.Broker.Integrity;

/// <summary>
/// Reports a failed integrity check: an <c>integrity-failure</c> line in the audit log and
/// a notice for the session agent (REQ-INT-3). The notice waits for a session agent that
/// is not connected yet, so a failure found at start still reaches the user.
/// </summary>
public sealed class IntegrityAlarm(AuditLog audit, Action<AgentMessage> notify)
{
    public void Raise(string detail)
    {
        try
        {
            audit.Append(new AuditEntry(DateTimeOffset.UtcNow, "integrity-failure", Detail: detail));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The notice below still goes out; an audit log that cannot be written is
            // reported by the next invocation, which it denies (REQ-AUD-7).
            detail += $" (The audit log could not record this: {e.Message})";
        }

        notify(new ShowNotice("OpWarden integrity warning", detail));
    }
}
