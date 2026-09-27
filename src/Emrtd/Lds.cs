using System.Text;

namespace Emrtd;

/// <summary>Logical Data Structure file identifiers and parsers (ICAO 9303 Part 10).</summary>
public static class Lds
{
    public const ushort CardAccess = 0x011C; // in the master file, read before PACE
    public const ushort Com = 0x011E;
    public const ushort Sod = 0x011D;

    public static ushort DataGroupFileId(int dataGroup) => (ushort)(0x0100 + dataGroup);

    private static readonly Dictionary<int, int> TagToDataGroup = new()
    {
        [0x61] = 1, [0x75] = 2, [0x63] = 3, [0x76] = 4, [0x65] = 5, [0x66] = 6, [0x67] = 7, [0x68] = 8,
        [0x69] = 9, [0x6A] = 10, [0x6B] = 11, [0x6C] = 12, [0x6D] = 13, [0x6E] = 14, [0x6F] = 15, [0x70] = 16,
    };

    /// <summary>EF.COM: LDS version, Unicode version and the list of data groups present.</summary>
    public static (string LdsVersion, IReadOnlyList<int> DataGroups) ParseCom(byte[] com)
    {
        var root = Tlv.Parse(com);
        string version = root.Find(0x5F01) is { } v ? Encoding.ASCII.GetString(v.Value) : "";
        var groups = root.Find(0x5C)?.Value.Select(t => TagToDataGroup.GetValueOrDefault(t)).Where(g => g > 0).ToList() ?? [];
        return (version, groups);
    }

    /// <summary>DG1: the MRZ as stored on the chip, split into lines.</summary>
    public static string[] ParseDg1(byte[] dg1)
    {
        string mrz = Encoding.ASCII.GetString(Tlv.Parse(dg1).Find(0x5F1F)?.Value
            ?? throw new FormatException("DG1 does not contain an MRZ (5F1F)."));
        int lineLength = mrz.Length switch { 90 => 30, 72 => 36, 88 => 44, _ => mrz.Length };
        return mrz.Chunk(lineLength).Select(c => new string(c)).ToArray();
    }

    /// <summary>DG2: the first face image (JPEG or JPEG 2000) inside the ISO 19794-5 biometric data block.</summary>
    public static FaceImage? ParseDg2(byte[] dg2)
    {
        var root = Tlv.Parse(dg2);
        byte[]? block = (root.Find(0x5F2E) ?? root.Find(0x7F2E))?.Value;
        if (block is null) return null;

        (byte[] Signature, string MimeType, string Extension)[] formats =
        [
            ([0xFF, 0xD8, 0xFF], "image/jpeg", ".jpg"),
            ([0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A], "image/jp2", ".jp2"),
            ([0xFF, 0x4F, 0xFF, 0x51], "image/j2k", ".j2k"),
        ];
        var match = formats
            .Select(f => (f.MimeType, f.Extension, Index: block.AsSpan().IndexOf(f.Signature)))
            .Where(f => f.Index >= 0)
            .OrderBy(f => f.Index)
            .FirstOrDefault();
        return match.MimeType is null ? null : new FaceImage(block[match.Index..], match.MimeType, match.Extension);
    }

    /// <summary>DG11 (additional personal details) and DG12 (additional document details) as name/value pairs.</summary>
    public static IReadOnlyDictionary<string, string> ParseDetails(byte[] dg)
    {
        var result = new Dictionary<string, string>();
        foreach (var field in Tlv.Parse(dg).Children)
        {
            if (field.Tag is 0x5C or 0xA0) continue; // tag list / "other names" count wrapper
            string name = DetailNames.GetValueOrDefault(field.Tag, $"Tag {field.Tag:X4}");
            string value = field.Tag is 0x5F1D or 0x5F1A ? $"<{field.Value.Length} bytes of image data>" : Encoding.UTF8.GetString(field.Value);
            result[name] = value.Replace('<', ' ').Trim();
        }
        return result;
    }

    private static readonly Dictionary<int, string> DetailNames = new()
    {
        [0x5F0E] = "Full name",
        [0x5F0F] = "Other name",
        [0x5F10] = "Personal number",
        [0x5F2B] = "Full date of birth",
        [0x5F11] = "Place of birth",
        [0x5F42] = "Address",
        [0x5F12] = "Telephone",
        [0x5F13] = "Profession",
        [0x5F14] = "Title",
        [0x5F15] = "Personal summary",
        [0x5F16] = "Proof of citizenship",
        [0x5F17] = "Other travel document numbers",
        [0x5F18] = "Custody information",
        [0x5F19] = "Issuing authority",
        [0x5F26] = "Date of issue",
        [0x5F1B] = "Endorsements / observations",
        [0x5F1C] = "Tax / exit requirements",
        [0x5F1D] = "Image of front",
        [0x5F1E] = "Image of rear",
        [0x5F55] = "Personalization date/time",
        [0x5F56] = "Personalization system serial number",
    };
}

public sealed record FaceImage(byte[] Data, string MimeType, string FileExtension);
