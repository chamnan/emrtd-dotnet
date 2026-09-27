namespace Emrtd;

/// <summary>ISO 7816-4 command APDU. <see cref="Ne"/> is the expected response length (null = none, 256 = "00").</summary>
public sealed record CommandApdu(byte Cla, byte Ins, byte P1, byte P2, byte[]? Data = null, int? Ne = null)
{
    public byte[] Encode()
    {
        int nc = Data?.Length ?? 0;
        bool extended = nc > 255 || Ne > 256;
        var apdu = new List<byte>(4 + nc + 5) { Cla, Ins, P1, P2 };

        if (nc > 0)
        {
            if (extended) apdu.AddRange([0x00, (byte)(nc >> 8), (byte)nc]);
            else apdu.Add((byte)nc);
            apdu.AddRange(Data!);
        }

        if (Ne is int ne)
        {
            if (extended)
            {
                if (nc == 0) apdu.Add(0x00);
                apdu.AddRange([(byte)(ne >> 8 & 0xFF), (byte)(ne & 0xFF)]); // 65536 encodes as 0000
            }
            else
            {
                apdu.Add((byte)(ne & 0xFF)); // 256 encodes as 00
            }
        }
        return [.. apdu];
    }

    public override string ToString() => Convert.ToHexString(Encode());
}

/// <summary>ISO 7816-4 response APDU.</summary>
public sealed record ResponseApdu(byte[] Data, ushort SW)
{
    public static ResponseApdu Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.Length < 2) throw new CardException(0, "Response shorter than a status word.");
        return new ResponseApdu(raw[..^2].ToArray(), (ushort)(raw[^2] << 8 | raw[^1]));
    }

    public bool IsSuccess => SW == 0x9000;

    /// <summary>Throws unless the status is 9000 (or 6282 "end of file reached", which still carries data).</summary>
    public ResponseApdu EnsureSuccess(string operation)
    {
        if (SW is 0x9000 or 0x6282) return this;
        throw new CardException(SW, $"{operation} failed");
    }

    public byte[] Encode() => [.. Data, (byte)(SW >> 8), (byte)SW];
}

public sealed class CardException(ushort sw, string message)
    : Exception(sw == 0 ? message : $"{message} (SW={sw:X4}: {StatusWords.Describe(sw)})")
{
    public ushort SW { get; } = sw;
}

public static class StatusWords
{
    public const ushort Success = 0x9000;
    public const ushort SecurityStatusNotSatisfied = 0x6982;
    public const ushort FileNotFound = 0x6A82;

    public static string Describe(ushort sw) => sw switch
    {
        0x9000 => "success",
        0x6282 => "end of file reached",
        0x6300 => "authentication failed",
        0x6700 => "wrong length",
        0x6882 => "secure messaging not supported",
        0x6982 => "security status not satisfied",
        0x6983 => "authentication method blocked",
        0x6984 => "reference data not usable",
        0x6985 => "conditions of use not satisfied",
        0x6986 => "command not allowed",
        0x6987 => "expected secure messaging objects missing",
        0x6988 => "secure messaging objects incorrect",
        0x6A80 => "incorrect data",
        0x6A82 => "file not found",
        0x6A86 => "incorrect P1/P2",
        0x6A88 => "referenced data not found",
        0x6B00 => "wrong parameters / offset outside file",
        0x6D00 => "instruction not supported",
        0x6E00 => "class not supported",
        _ => "unknown",
    };
}
