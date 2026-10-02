namespace OpWarden.Core;

/// <summary>
/// The category of an op CLI invocation (spec section 6). <see cref="Unknown"/> is
/// what REQ-CLAS-8 calls an unknown action: it still gets a verdict, never a free pass.
/// </summary>
public enum OpAction
{
    Unknown,
    Read,
    Write,
    Delete,
    Manage,
    Run,
    Meta,
}
