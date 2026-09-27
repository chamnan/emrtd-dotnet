using System.Security.Cryptography;
using System.Text;

namespace Emrtd;

/// <summary>
/// The MRZ-derived access key used by BAC and PACE: document number, date of birth and
/// date of expiry, each followed by its check digit (ICAO 9303 Part 11 §9.7.2 / §9.7.3).
/// </summary>
public sealed record MrzKey
{
    public MrzKey(string documentNumber, string dateOfBirth, string dateOfExpiry)
    {
        DocumentNumber = documentNumber.Trim().ToUpperInvariant();
        DateOfBirth = dateOfBirth.Trim();
        DateOfExpiry = dateOfExpiry.Trim();

        if (DocumentNumber.Length == 0 || DocumentNumber.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '<'))
            throw new ArgumentException("Document number must be A-Z, 0-9 or '<'.", nameof(documentNumber));
        if (DateOfBirth.Length != 6 || !DateOfBirth.All(char.IsAsciiDigit))
            throw new ArgumentException("Date of birth must be YYMMDD.", nameof(dateOfBirth));
        if (DateOfExpiry.Length != 6 || !DateOfExpiry.All(char.IsAsciiDigit))
            throw new ArgumentException("Date of expiry must be YYMMDD.", nameof(dateOfExpiry));
    }

    public string DocumentNumber { get; }
    public string DateOfBirth { get; }
    public string DateOfExpiry { get; }

    /// <summary>
    /// "MRZ_information": document number (padded to at least 9 characters) + check digit,
    /// date of birth + check digit, date of expiry + check digit.
    /// </summary>
    public string MrzInformation
    {
        get
        {
            string number = DocumentNumber.PadRight(9, '<');
            return number + CheckDigit(number) + DateOfBirth + CheckDigit(DateOfBirth) + DateOfExpiry + CheckDigit(DateOfExpiry);
        }
    }

    /// <summary>SHA-1 of the MRZ information. BAC uses the first 16 bytes as Kseed; PACE uses all 20 as the password key.</summary>
    public byte[] Hash() => SHA1.HashData(Encoding.ASCII.GetBytes(MrzInformation));

    /// <summary>
    /// Builds the key from raw MRZ text (TD1 = 3×30, TD2 = 2×36, TD3 = 2×44). Lines may be separated by
    /// newlines or '|'. The OCR step should already have validated the check digits.
    /// </summary>
    public static MrzKey FromMrz(string mrz)
    {
        string[] lines = mrz.Split(['\n', '\r', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        switch (lines)
        {
            case [{ Length: 30 } l1, { Length: 30 } l2, { Length: 30 }]:
            {
                string number = l1[5..14];
                // Document numbers longer than 9 characters continue in the optional field (check digit '<' at 14).
                if (l1[14] == '<' && l1[15..30].IndexOf('<') is var end and > 1)
                    number += l1[15..(15 + end - 1)];
                return new MrzKey(number.TrimEnd('<'), l2[0..6], l2[8..14]);
            }
            case [{ Length: 36 or 44 }, { Length: 36 or 44 } l2]:
                return new MrzKey(l2[0..9].TrimEnd('<'), l2[13..19], l2[21..27]);
            default:
                throw new FormatException("MRZ must be 3 lines of 30 (TD1) or 2 lines of 36/44 (TD2/TD3) characters.");
        }
    }

    public static char CheckDigit(string data)
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
        return (char)('0' + sum % 10);
    }
}
