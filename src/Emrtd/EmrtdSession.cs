namespace Emrtd;

/// <summary>
/// A connection to the eMRTD chip. Sends commands in plain text until secure messaging is
/// started, then wraps every command. Provides SELECT and chunked READ BINARY.
/// </summary>
public sealed class EmrtdSession(ICardTransport transport, Action<string>? log = null)
{
    /// <summary>eMRTD LDS1 application identifier.</summary>
    public static readonly byte[] AppletAid = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

    private SecureMessaging? _sm;

    /// <summary>
    /// Maximum bytes per READ BINARY. 0xDF keeps the protected response within a short APDU,
    /// which every reader and chip supports (the same default as JMRTD).
    /// </summary>
    public int MaxReadSize { get; init; } = 0xDF;

    public ICardTransport Transport => transport;

    public bool IsSecure => _sm is not null;

    public void StartSecureMessaging(SecureMessaging sm) => _sm = sm;

    public void StopSecureMessaging() => _sm = null;

    internal void Log(string message) => log?.Invoke(message);

    public ResponseApdu Send(CommandApdu command)
    {
        if (_sm is null) return ResponseApdu.Parse(transport.Transmit(command.Encode()));
        return _sm.Unwrap(transport.Transmit(_sm.Wrap(command)));
    }

    public void SelectApplet() =>
        Send(new CommandApdu(0x00, 0xA4, 0x04, 0x0C, AppletAid)).EnsureSuccess("SELECT eMRTD application");

    public ResponseApdu SelectFile(ushort fileId) =>
        Send(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, [(byte)(fileId >> 8), (byte)fileId]));

    /// <summary>Selects and reads a whole elementary file. The TLV header tells how much to read.</summary>
    public byte[] ReadFile(ushort fileId)
    {
        SelectFile(fileId).EnsureSuccess($"SELECT file {fileId:X4}");
        return ReadSelectedFile(offset => ReadBinary(offset, 8));
    }

    /// <summary>Reads a file by short file identifier (READ BINARY with P1 = 0x80 | SFI) without selecting it first.</summary>
    public byte[] ReadFileBySfi(byte sfi) =>
        ReadSelectedFile(_ => Send(new CommandApdu(0x00, 0xB0, (byte)(0x80 | sfi), 0x00, Ne: 8))
            .EnsureSuccess($"READ BINARY (SFI {sfi:X2})").Data);

    /// <summary>Like <see cref="ReadFile"/>, but returns null when the file is absent or access is denied.</summary>
    public byte[]? TryReadFile(ushort fileId)
    {
        var select = SelectFile(fileId);
        if (select.SW is StatusWords.FileNotFound or StatusWords.SecurityStatusNotSatisfied or 0x6A86 or 0x6A88)
        {
            Log($"File {fileId:X4} not available ({StatusWords.Describe(select.SW)}).");
            return null;
        }
        select.EnsureSuccess($"SELECT file {fileId:X4}");

        try
        {
            return ReadSelectedFile(offset => ReadBinary(offset, 8));
        }
        catch (CardException ex) when (ex.SW == StatusWords.SecurityStatusNotSatisfied)
        {
            Log($"File {fileId:X4}: access denied (needs EAC).");
            return null;
        }
    }

    private byte[] ReadSelectedFile(Func<int, byte[]> readHeader)
    {
        byte[] header = readHeader(0);
        int total = Tlv.TotalLength(header);
        if (total <= header.Length) return header[..total];

        var content = new byte[total];
        header.CopyTo(content, 0);
        int offset = header.Length;
        while (offset < total)
        {
            byte[] chunk = ReadBinary(offset, Math.Min(MaxReadSize, total - offset));
            if (chunk.Length == 0) throw new CardException(0, $"READ BINARY returned no data at offset {offset}.");
            chunk.CopyTo(content, offset);
            offset += chunk.Length;
        }
        return content;
    }

    private byte[] ReadBinary(int offset, int length)
    {
        if (offset > 0x7FFF)
            throw new NotSupportedException("Files larger than 32 KB need READ BINARY with odd INS (B1), which is not implemented.");
        return Send(new CommandApdu(0x00, 0xB0, (byte)(offset >> 8), (byte)offset, Ne: length))
            .EnsureSuccess($"READ BINARY at {offset}").Data;
    }
}
