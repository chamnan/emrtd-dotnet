using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

namespace MrzReader;

internal enum MrzFormat { TD1, TD2, TD3 }

internal sealed record CheckResult(string Field, bool Valid);

internal sealed class MrzResult
{
    public required MrzFormat Format { get; init; }
    public required string[] Lines { get; init; }
    public required string DocumentCode { get; init; }
    public required string IssuingState { get; init; }
    public required string DocumentNumber { get; init; }
    public required string Surname { get; init; }
    public required string GivenNames { get; init; }
    public required string Nationality { get; init; }
    public required DateOnly? DateOfBirth { get; init; }
    public required string Sex { get; init; }
    public required DateOnly? DateOfExpiry { get; init; }
    public required string OptionalData1 { get; init; }
    public required string OptionalData2 { get; init; }
    public required List<CheckResult> Checks { get; init; }

    public int ValidChecks => Checks.Count(c => c.Valid);
    public bool IsValid => Checks.All(c => c.Valid);
}

/// <summary>Finds and parses ICAO 9303 machine readable zones (TD1, TD2, TD3) in OCR text.</summary>
internal static partial class MrzParser
{
    // Per-position character classes: N = digit, A = letter or filler, * = anything.
    // Used to undo the usual OCR confusions (O/0, I/1, S/5, B/8, ...).
    private static readonly Dictionary<MrzFormat, string[]> Masks = new()
    {
        [MrzFormat.TD1] =
        [
            "AAAAA*********N***************",
            "NNNNNNNANNNNNNNAAA***********N",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ],
        [MrzFormat.TD2] =
        [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "*********NAAANNNNNNNANNNNNNN*******N",
        ],
        [MrzFormat.TD3] =
        [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "*********NAAANNNNNNNANNNNNNN**************NN",
        ],
    };

    private static readonly Dictionary<char, char> ToDigit = new()
    {
        ['O'] = '0', ['Q'] = '0', ['D'] = '0', ['I'] = '1', ['L'] = '1', ['T'] = '7',
        ['Z'] = '2', ['S'] = '5', ['G'] = '6', ['B'] = '8',
    };

    private static readonly Dictionary<char, char> ToLetter = new()
    {
        ['0'] = 'O', ['1'] = 'I', ['2'] = 'Z', ['5'] = 'S', ['6'] = 'G', ['8'] = 'B',
    };

    [GeneratedRegex("[^A-Z0-9<]")]
    private static partial Regex NonMrzChars();

    public static MrzResult? Parse(string ocrText)
    {
        var candidates = ocrText
            .Split('\n')
            .Select(l => NonMrzChars().Replace(l.ToUpperInvariant().Replace('«', '<'), ""))
            .Where(l => l.Length >= 20)
            .ToList();

        MrzResult? best = null;
        foreach (var (format, length, count) in new[] { (MrzFormat.TD1, 30, 3), (MrzFormat.TD3, 44, 2), (MrzFormat.TD2, 36, 2) })
        {
            // Try every run of consecutive lines whose lengths are close to the format's line length.
            for (int start = 0; start + count <= candidates.Count; start++)
            {
                var block = candidates.Skip(start).Take(count).ToArray();
                if (block.Any(l => Math.Abs(l.Length - length) > 4)) continue;

                var lines = block.Select((l, i) => Correct(FixLength(l, length), Masks[format][i])).ToArray();
                var result = format switch
                {
                    MrzFormat.TD1 => ParseTd1(lines),
                    MrzFormat.TD2 => ParseTd2Or3(lines, MrzFormat.TD2),
                    _ => ParseTd2Or3(lines, MrzFormat.TD3),
                };
                if (best is null || result.ValidChecks > best.ValidChecks) best = result;
            }
        }
        return best;
    }

    private static MrzResult ParseTd1(string[] l)
    {
        string docNumber = l[0][5..14];
        char docCheck = l[0][14];
        string optional1 = l[0][15..30];

        // Long document numbers overflow into the optional field; the check digit then follows the overflow.
        if (docCheck == '<' && optional1.IndexOf('<') is var end and > 0)
        {
            docNumber += optional1[..(end - 1)];
            docCheck = optional1[end - 1];
            optional1 = optional1[end..];
        }
        (docNumber, bool docValid) = RepairWithCheckDigit(docNumber, docCheck);

        var checks = new List<CheckResult>
        {
            new("Document number", docValid),
            new("Date of birth", IsValid(l[1][0..6], l[1][6])),
            new("Date of expiry", IsValid(l[1][8..14], l[1][14])),
            new("Composite", IsValid(l[0][5..30] + l[1][0..7] + l[1][8..15] + l[1][18..29], l[1][29])),
        };
        var (surname, given) = ParseNames(l[2]);

        return new MrzResult
        {
            Format = MrzFormat.TD1,
            Lines = l,
            DocumentCode = Clean(l[0][0..2]),
            IssuingState = Clean(l[0][2..5]),
            DocumentNumber = Clean(docNumber),
            Surname = surname,
            GivenNames = given,
            Nationality = Clean(l[1][15..18]),
            DateOfBirth = ParseDate(l[1][0..6], isExpiry: false),
            Sex = Clean(l[1][7..8]),
            DateOfExpiry = ParseDate(l[1][8..14], isExpiry: true),
            OptionalData1 = Clean(optional1),
            OptionalData2 = Clean(l[1][18..29]),
            Checks = checks,
        };
    }

    private static MrzResult ParseTd2Or3(string[] l, MrzFormat format)
    {
        int last = l[1].Length - 1; // composite check digit position
        int optionalEnd = format == MrzFormat.TD3 ? 42 : last;
        (string docNumber, bool docValid) = RepairWithCheckDigit(l[1][0..9], l[1][9]);

        var checks = new List<CheckResult>
        {
            new("Document number", docValid),
            new("Date of birth", IsValid(l[1][13..19], l[1][19])),
            new("Date of expiry", IsValid(l[1][21..27], l[1][27])),
        };
        if (format == MrzFormat.TD3)
            checks.Add(new("Personal number", IsValid(l[1][28..42], l[1][42])));
        checks.Add(new("Composite", IsValid(l[1][0..10] + l[1][13..20] + l[1][21..last], l[1][last])));

        var (surname, given) = ParseNames(l[0][5..]);
        return new MrzResult
        {
            Format = format,
            Lines = l,
            DocumentCode = Clean(l[0][0..2]),
            IssuingState = Clean(l[0][2..5]),
            DocumentNumber = Clean(docNumber),
            Surname = surname,
            GivenNames = given,
            Nationality = Clean(l[1][10..13]),
            DateOfBirth = ParseDate(l[1][13..19], isExpiry: false),
            Sex = Clean(l[1][20..21]),
            DateOfExpiry = ParseDate(l[1][21..27], isExpiry: true),
            OptionalData1 = Clean(l[1][28..optionalEnd]),
            OptionalData2 = "",
            Checks = checks,
        };
    }

    /// <summary>ICAO 9303 check digit: weights 7-3-1, digits as-is, A-Z = 10-35, filler = 0.</summary>
    public static int CheckDigit(string data)
    {
        ReadOnlySpan<int> weights = [7, 3, 1];
        int sum = 0;
        for (int i = 0; i < data.Length; i++)
        {
            char c = data[i];
            int value = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'A' and <= 'Z' => c - 'A' + 10,
                _ => 0,
            };
            sum += value * weights[i % 3];
        }
        return sum % 10;
    }

    private static bool IsValid(string data, char check) =>
        CheckDigit(data) == (check == '<' ? 0 : check - '0');

    /// <summary>
    /// Document numbers are alphanumeric, so the mask cannot fix O/0-style confusions.
    /// If the check digit fails, try swapping look-alike characters until it passes.
    /// </summary>
    private static (string Value, bool Valid) RepairWithCheckDigit(string value, char check)
    {
        if (IsValid(value, check)) return (value, true);

        var ambiguous = Enumerable.Range(0, value.Length)
            .Where(i => ToDigit.ContainsKey(value[i]) || ToLetter.ContainsKey(value[i]))
            .Take(10)
            .ToArray();

        // Fewest substitutions first, so the most likely correction wins.
        var masks = Enumerable.Range(1, (1 << ambiguous.Length) - 1).OrderBy(m => BitOperations.PopCount((uint)m));
        foreach (int mask in masks)
        {
            var chars = value.ToCharArray();
            for (int bit = 0; bit < ambiguous.Length; bit++)
            {
                if ((mask & (1 << bit)) == 0) continue;
                char c = chars[ambiguous[bit]];
                chars[ambiguous[bit]] = ToDigit.TryGetValue(c, out char d) ? d : ToLetter[c];
            }
            var candidate = new string(chars);
            if (IsValid(candidate, check)) return (candidate, true);
        }
        return (value, false);
    }

    private static string FixLength(string line, int length)
    {
        // OCR most often miscounts long runs of '<' fillers, so grow/shrink the longest run.
        while (line.Length != length)
        {
            var run = FillerRuns().Matches(line).MaxBy(m => m.Length);
            if (line.Length > length)
                line = run is not null ? line.Remove(run.Index, 1) : line[..length];
            else
                line = run is not null ? line.Insert(run.Index, "<") : line.PadRight(length, '<');
        }
        return line;
    }

    [GeneratedRegex("<+")]
    private static partial Regex FillerRuns();

    private static string Correct(string line, string mask)
    {
        var sb = new StringBuilder(line);
        for (int i = 0; i < sb.Length; i++)
        {
            char c = sb[i];
            if (mask[i] == 'N' && ToDigit.TryGetValue(c, out char digit)) sb[i] = digit;
            else if (mask[i] == 'A' && ToLetter.TryGetValue(c, out char letter)) sb[i] = letter;
        }
        return sb.ToString();
    }

    private static (string Surname, string GivenNames) ParseNames(string field)
    {
        // Everything after a long filler run is padding; stray letters there are OCR noise (usually '<' read as 'K').
        int padding = field.IndexOf("<<<", StringComparison.Ordinal);
        if (padding >= 0) field = field[..padding];

        int separator = field.IndexOf("<<", StringComparison.Ordinal);
        string surname = separator >= 0 ? field[..separator] : field;
        string given = separator >= 0 ? field[(separator + 2)..] : "";
        return (Clean(surname), Clean(given));
    }

    private static DateOnly? ParseDate(string yymmdd, bool isExpiry)
    {
        if (!DateOnly.TryParseExact(yymmdd, "yyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date))
            return null;

        // Resolve the century: birth dates are never in the future, expiry dates rarely more than ~50 years out.
        int yy = date.Year % 100;
        int currentYy = DateTime.Today.Year % 100;
        int century = isExpiry
            ? (yy <= currentYy + 50 ? 2000 : 1900)
            : (yy <= currentYy ? 2000 : 1900);
        return new DateOnly(century + yy, date.Month, date.Day);
    }

    private static string Clean(string value) => value.Replace('<', ' ').Trim();
}
