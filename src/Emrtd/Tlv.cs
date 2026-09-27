namespace Emrtd;

/// <summary>BER-TLV data object as used by ISO 7816-4 and the ICAO LDS.</summary>
public sealed record Tlv(int Tag, byte[] Value)
{
    public bool IsConstructed => (FirstTagByte(Tag) & 0x20) != 0;

    public IReadOnlyList<Tlv> Children => IsConstructed ? ParseAll(Value) : [];

    /// <summary>Depth-first search for the first object with <paramref name="tag"/> (including this one).</summary>
    public Tlv? Find(int tag)
    {
        if (Tag == tag) return this;
        foreach (var child in Children)
            if (child.Find(tag) is { } found) return found;
        return null;
    }

    public static Tlv Parse(ReadOnlySpan<byte> data) => Parse(data, out _);

    public static Tlv Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        int offset = 0;
        int tag = ReadTag(data, ref offset);
        int length = ReadLength(data, ref offset);
        if (offset + length > data.Length)
            throw new FormatException($"TLV {tag:X} declares {length} bytes but only {data.Length - offset} remain.");
        consumed = offset + length;
        return new Tlv(tag, data.Slice(offset, length).ToArray());
    }

    public static List<Tlv> ParseAll(ReadOnlySpan<byte> data)
    {
        var result = new List<Tlv>();
        while (data.Length > 0)
        {
            // Some chips pad files with 00 or FF after the last object.
            if (data[0] is 0x00 or 0xFF) break;
            result.Add(Parse(data, out int consumed));
            data = data[consumed..];
        }
        return result;
    }

    /// <summary>Returns the total size (tag + length + value) declared by the TLV header at the start of <paramref name="header"/>.</summary>
    public static int TotalLength(ReadOnlySpan<byte> header)
    {
        int offset = 0;
        ReadTag(header, ref offset);
        int length = ReadLength(header, ref offset);
        return offset + length;
    }

    public static byte[] Encode(int tag, ReadOnlySpan<byte> value)
    {
        var output = new List<byte>(value.Length + 8);
        for (int shift = 24; shift >= 0; shift -= 8)
        {
            byte b = (byte)(tag >> shift);
            if (b != 0 || output.Count > 0 || shift == 0) output.Add(b);
        }
        output.AddRange(EncodeLength(value.Length));
        output.AddRange(value.ToArray());
        return [.. output];
    }

    public byte[] Encode() => Encode(Tag, Value);

    public static byte[] EncodeLength(int length) => length switch
    {
        < 0x80 => [(byte)length],
        <= 0xFF => [0x81, (byte)length],
        <= 0xFFFF => [0x82, (byte)(length >> 8), (byte)length],
        _ => [0x83, (byte)(length >> 16), (byte)(length >> 8), (byte)length],
    };

    private static int ReadTag(ReadOnlySpan<byte> data, ref int offset)
    {
        int tag = data[offset++];
        if ((tag & 0x1F) == 0x1F)
        {
            byte b;
            do
            {
                b = data[offset++];
                tag = tag << 8 | b;
            } while ((b & 0x80) != 0);
        }
        return tag;
    }

    private static int ReadLength(ReadOnlySpan<byte> data, ref int offset)
    {
        int first = data[offset++];
        if (first < 0x80) return first;

        int count = first & 0x7F;
        if (count is 0 or > 4) throw new FormatException($"Unsupported BER length form 0x{first:X2}.");
        int length = 0;
        for (int i = 0; i < count; i++) length = length << 8 | data[offset++];
        return length;
    }

    private static int FirstTagByte(int tag)
    {
        while (tag > 0xFF) tag >>= 8;
        return tag;
    }
}
