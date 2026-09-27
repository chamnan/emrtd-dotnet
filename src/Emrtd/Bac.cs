using System.Security.Cryptography;

namespace Emrtd;

/// <summary>Basic Access Control (ICAO 9303 Part 11 §4.3). Always 3DES; requires the eMRTD applet to be selected.</summary>
public static class Bac
{
    public static SecureMessaging Authenticate(EmrtdSession session, MrzKey key) =>
        Authenticate(session, key, RandomNumberGenerator.GetBytes(8), RandomNumberGenerator.GetBytes(16));

    /// <summary>Overload with fixed randoms so the ICAO worked example can be reproduced in tests.</summary>
    internal static SecureMessaging Authenticate(EmrtdSession session, MrzKey key, byte[] rndIfd, byte[] kIfd)
    {
        byte[] seed = key.Hash()[..16];
        byte[] kEnc = Crypto.Kdf(seed, Crypto.KdfEnc, SmCipher.TripleDes);
        byte[] kMac = Crypto.Kdf(seed, Crypto.KdfMac, SmCipher.TripleDes);

        byte[] rndIc = session.Send(new CommandApdu(0x00, 0x84, 0x00, 0x00, Ne: 8)).EnsureSuccess("GET CHALLENGE").Data;
        if (rndIc.Length != 8) throw new CardException(0, $"GET CHALLENGE returned {rndIc.Length} bytes, expected 8.");

        byte[] eIfd = Crypto.Encrypt(SmCipher.TripleDes, kEnc, [.. rndIfd, .. rndIc, .. kIfd], new byte[8]);
        byte[] mIfd = Crypto.Mac(SmCipher.TripleDes, kMac, Crypto.Pad(eIfd, 8));

        var response = session.Send(new CommandApdu(0x00, 0x82, 0x00, 0x00, [.. eIfd, .. mIfd], Ne: 40));
        if (response.SW == 0x6300)
            throw new CardException(response.SW, "BAC rejected: the MRZ (document number / birth / expiry) does not match the chip");
        byte[] r = response.EnsureSuccess("EXTERNAL AUTHENTICATE").Data;
        if (r.Length != 40) throw new CardException(0, $"EXTERNAL AUTHENTICATE returned {r.Length} bytes, expected 40.");

        byte[] eIc = r[..32];
        if (!CryptographicOperations.FixedTimeEquals(Crypto.Mac(SmCipher.TripleDes, kMac, Crypto.Pad(eIc, 8)), r[32..]))
            throw new CryptographicException("BAC: chip MAC is invalid.");

        byte[] plain = Crypto.Decrypt(SmCipher.TripleDes, kEnc, eIc, new byte[8]);
        if (!plain.AsSpan(0, 8).SequenceEqual(rndIc) || !plain.AsSpan(8, 8).SequenceEqual(rndIfd))
            throw new CryptographicException("BAC: chip response does not contain our challenge.");

        byte[] kIc = plain[16..32];
        byte[] sessionSeed = new byte[16];
        for (int i = 0; i < 16; i++) sessionSeed[i] = (byte)(kIfd[i] ^ kIc[i]);

        byte[] ssc = [.. rndIc[4..8], .. rndIfd[4..8]];
        return new SecureMessaging(SmCipher.TripleDes,
            Crypto.Kdf(sessionSeed, Crypto.KdfEnc, SmCipher.TripleDes),
            Crypto.Kdf(sessionSeed, Crypto.KdfMac, SmCipher.TripleDes),
            ssc);
    }
}
