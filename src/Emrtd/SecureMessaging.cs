using System.Security.Cryptography;

namespace Emrtd;

/// <summary>
/// ICAO 9303 Part 11 §9.8 secure messaging: wraps command APDUs (DO87/DO97/DO8E) and
/// unwraps/verifies responses (DO87/DO99/DO8E). The send sequence counter (SSC) is
/// incremented once per command and once per response.
/// </summary>
public sealed class SecureMessaging
{
    private readonly byte[] _ksEnc;
    private readonly byte[] _ksMac;
    private readonly byte[] _ssc;

    public SecureMessaging(SmCipher cipher, byte[] ksEnc, byte[] ksMac, byte[] ssc)
    {
        Cipher = cipher;
        _ksEnc = ksEnc;
        _ksMac = ksMac;
        _ssc = (byte[])ssc.Clone();
        if (_ssc.Length != BlockSize) throw new ArgumentException($"SSC must be {BlockSize} bytes.", nameof(ssc));
    }

    public SmCipher Cipher { get; }

    private int BlockSize => Crypto.BlockSize(Cipher);

    internal byte[] Ssc => (byte[])_ssc.Clone();

    public byte[] Wrap(CommandApdu command)
    {
        IncrementSsc();

        byte cla = (byte)(command.Cla | 0x0C);
        byte[] header = Crypto.Pad([cla, command.Ins, command.P1, command.P2], BlockSize);

        byte[] do87 = [];
        if (command.Data is { Length: > 0 } data)
        {
            byte[] encrypted = Crypto.Encrypt(Cipher, _ksEnc, Crypto.Pad(data, BlockSize), Iv());
            // Odd INS (e.g. READ BINARY B1) uses DO85 without the padding-content indicator.
            do87 = (command.Ins & 1) == 0
                ? Tlv.Encode(0x87, [0x01, .. encrypted])
                : Tlv.Encode(0x85, encrypted);
        }

        byte[] do97 = [];
        if (command.Ne is int ne)
            do97 = ne > 256 ? Tlv.Encode(0x97, [(byte)(ne >> 8), (byte)ne]) : Tlv.Encode(0x97, [(byte)ne]);

        byte[] mac = Crypto.Mac(Cipher, _ksMac, Crypto.Pad([.. _ssc, .. header, .. do87, .. do97], BlockSize));
        byte[] do8E = Tlv.Encode(0x8E, mac);

        byte[] body = [.. do87, .. do97, .. do8E];
        bool extended = body.Length > 255 || command.Ne > 256;
        return new CommandApdu(cla, command.Ins, command.P1, command.P2, body, extended ? 65536 : 256).Encode();
    }

    public ResponseApdu Unwrap(byte[] rawResponse)
    {
        IncrementSsc();
        var response = ResponseApdu.Parse(rawResponse);

        // Some chips answer errors in plain text; the session is effectively over after that.
        if (response.Data.Length == 0)
        {
            if (response.IsSuccess) throw new CardException(response.SW, "Secure messaging response without MAC");
            return response;
        }

        byte[]? encrypted = null, do99 = null, cc = null;
        var macInput = new List<byte>(_ssc);
        foreach (var obj in Tlv.ParseAll(response.Data))
        {
            switch (obj.Tag)
            {
                case 0x87:
                    encrypted = obj.Value[1..]; // skip padding-content indicator 01
                    macInput.AddRange(obj.Encode());
                    break;
                case 0x85:
                    encrypted = obj.Value;
                    macInput.AddRange(obj.Encode());
                    break;
                case 0x99:
                    do99 = obj.Value;
                    macInput.AddRange(obj.Encode());
                    break;
                case 0x8E:
                    cc = obj.Value;
                    break;
            }
        }

        if (cc is null) throw new CardException(response.SW, "Secure messaging response is missing DO8E (MAC)");
        byte[] expected = Crypto.Mac(Cipher, _ksMac, Crypto.Pad([.. macInput], BlockSize));
        if (!CryptographicOperations.FixedTimeEquals(expected, cc))
            throw new CryptographicException("Secure messaging MAC verification failed.");

        ushort sw = do99 is { Length: 2 } ? (ushort)(do99[0] << 8 | do99[1]) : response.SW;
        byte[] plain = encrypted is null ? [] : Crypto.Unpad(Crypto.Decrypt(Cipher, _ksEnc, encrypted, Iv()));
        return new ResponseApdu(plain, sw);
    }

    // 3DES uses a zero IV; AES uses IV = E(KSenc, SSC) (Part 11 §9.8.6.3).
    private byte[] Iv() => Cipher == SmCipher.TripleDes ? new byte[8] : Crypto.AesEcb(_ksEnc, _ssc);

    private void IncrementSsc()
    {
        for (int i = _ssc.Length - 1; i >= 0; i--)
            if (++_ssc[i] != 0) break;
    }
}
