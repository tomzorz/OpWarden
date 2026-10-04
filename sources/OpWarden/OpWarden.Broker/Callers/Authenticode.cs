using System.Runtime.InteropServices;

namespace OpWarden.Broker.Callers;

/// <summary>
/// Who signed an executable, by its embedded Authenticode signature (REQ-CALL-14).
/// </summary>
/// <remarks>
/// Verification never touches the network: revocation checks are off and URL retrieval
/// is cache-only, because a caller waits on this and an offline machine must not stall.
/// Results are kept per path, size and modification time, so a file replaced in place is
/// verified again.
/// </remarks>
public static unsafe partial class Authenticode
{
    private static readonly Lock Gate = new();
    private static readonly Dictionary<(string Path, long Size, DateTime Modified), string?> Verified = [];

    /// <summary>
    /// The signer's display name (<c>Anthropic, PBC</c>), or null when the file is not
    /// validly signed or cannot be read.
    /// </summary>
    public static string? SignerOf(string path)
    {
        FileInfo file;
        try
        {
            file = new FileInfo(path);
            if (!file.Exists) return null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }

        var key = (file.FullName.ToUpperInvariant(), file.Length, file.LastWriteTimeUtc);
        lock (Gate)
        {
            if (Verified.TryGetValue(key, out var cached)) return cached;
        }

        var signer = Verify(file.FullName);
        lock (Gate) Verified[key] = signer;
        return signer;
    }

    private static string? Verify(string path)
    {
        fixed (char* filePath = path)
        {
            var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)sizeof(WINTRUST_FILE_INFO), pcwszFilePath = filePath };
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)sizeof(WINTRUST_DATA),
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pFile = &fileInfo,
                dwStateAction = WtdStateActionVerify,
                dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
            };
            var action = GenericVerifyV2;
            var trusted = WinVerifyTrust(-1, &action, &data) == 0;
            try
            {
                return trusted ? SignerName(data.hWVTStateData) : null;
            }
            finally
            {
                data.dwStateAction = WtdStateActionClose;
                _ = WinVerifyTrust(-1, &action, &data);
            }
        }
    }

    private static string? SignerName(nint state)
    {
        var provider = WTHelperProvDataFromStateData(state);
        if (provider == 0) return null;
        var signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if (signer == 0) return null;

        // CRYPT_PROVIDER_SGNR: the certificate chain pointer sits at offset 16, and the leaf
        // CRYPT_PROVIDER_CERT holds its CERT_CONTEXT pointer at offset 8.
        var chain = *(nint*)(signer + 16);
        if (chain == 0) return null;
        var certificate = *(nint*)(chain + 8);

        var name = stackalloc char[256];
        var length = CertGetNameStringW(certificate, CertNameSimpleDisplayType, 0, null, name, 256);
        return length > 1 ? new string(name, 0, (int)length - 1) : null;
    }

    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    private const uint WtdUiNone = 2, WtdRevokeNone = 0, WtdChoiceFile = 1, WtdStateActionVerify = 1, WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10, WtdCacheOnlyUrlRetrieval = 0x1000, CertNameSimpleDisplayType = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public char* pcwszFilePath;
        public nint hFile;
        public Guid* pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public nint pPolicyCallbackData, pSIPClientData;
        public uint dwUIChoice, fdwRevocationChecks, dwUnionChoice;
        public WINTRUST_FILE_INFO* pFile;
        public uint dwStateAction;
        public nint hWVTStateData;
        public char* pwszURLReference;
        public uint dwProvFlags, dwUIContext;
        public nint pSignatureSettings;
    }

    [LibraryImport("wintrust.dll")] private static partial int WinVerifyTrust(nint window, Guid* action, WINTRUST_DATA* data);
    [LibraryImport("wintrust.dll")] private static partial nint WTHelperProvDataFromStateData(nint state);
    [LibraryImport("wintrust.dll")] private static partial nint WTHelperGetProvSignerFromChain(nint provider, uint signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterSignerIndex);
    [LibraryImport("crypt32.dll")] private static partial uint CertGetNameStringW(nint certificate, uint type, uint flags, void* typeParameter, char* name, uint length);
}
