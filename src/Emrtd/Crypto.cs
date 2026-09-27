using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Emrtd;

/// <summary>Cipher used for secure messaging, selected by BAC (always 3DES) or by the PACE protocol OID.</summary>
public enum SmCipher { TripleDes, Aes128, Aes192, Aes256 }

/// <summary>Cryptographic primitives from ICAO Doc 9303 Part 11 (§9.7 key derivation, §9.8 secure messaging).</summary>
internal static class Crypto
{
    public const int KdfEnc = 1;
    public const int KdfMac = 2;
    public const int KdfPace = 3;

    public static int BlockSize(SmCipher cipher) => cipher == SmCipher.TripleDes ? 8 : 16;

    /// <summary>KDF(K, c) = H(K || c), c as 32-bit big-endian; truncated / parity-adjusted for the cipher.</summary>
    public static byte[] Kdf(ReadOnlySpan<byte> sharedSecret, int counter, SmCipher cipher)
    {
        byte[] input = [.. sharedSecret, 0, 0, 0, (byte)counter];
        return cipher switch
        {
            SmCipher.TripleDes => AdjustDesParity(SHA1.HashData(input)[..16]),
            SmCipher.Aes128 => SHA1.HashData(input)[..16],
            SmCipher.Aes192 => SHA256.HashData(input)[..24],
            _ => SHA256.HashData(input),
        };
    }

    /// <summary>Sets the least significant bit of each byte so every byte has odd parity (DES key convention).</summary>
    public static byte[] AdjustDesParity(byte[] key)
    {
        for (int i = 0; i < key.Length; i++)
        {
            int b = key[i] & 0xFE;
            int ones = System.Numerics.BitOperations.PopCount((uint)b);
            key[i] = (byte)(b | (ones % 2 == 0 ? 1 : 0));
        }
        return key;
    }

    public static byte[] Encrypt(SmCipher cipher, byte[] key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv)
    {
        using SymmetricAlgorithm algorithm = Create(cipher, key);
        return algorithm.EncryptCbc(data, iv, PaddingMode.None);
    }

    public static byte[] Decrypt(SmCipher cipher, byte[] key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv)
    {
        using SymmetricAlgorithm algorithm = Create(cipher, key);
        return algorithm.DecryptCbc(data, iv, PaddingMode.None);
    }

    /// <summary>Single-block AES-ECB, used to derive the SM IV from the send sequence counter.</summary>
    public static byte[] AesEcb(byte[] key, ReadOnlySpan<byte> block)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptEcb(block, PaddingMode.None);
    }

    /// <summary>
    /// 8-byte MAC. 3DES: ISO 9797-1 MAC algorithm 3 ("retail MAC"); AES: CMAC truncated to 8 bytes.
    /// The caller is responsible for any padding the protocol requires.
    /// </summary>
    public static byte[] Mac(SmCipher cipher, byte[] key, ReadOnlySpan<byte> data)
    {
        Org.BouncyCastle.Crypto.IMac mac = cipher == SmCipher.TripleDes
            ? new ISO9797Alg3Mac(new DesEngine())
            : new CMac(new AesEngine(), 64);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data);
        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    /// <summary>ISO/IEC 9797-1 padding method 2: append 0x80 then zeros up to the block size.</summary>
    public static byte[] Pad(ReadOnlySpan<byte> data, int blockSize)
    {
        int length = (data.Length / blockSize + 1) * blockSize;
        var output = new byte[length];
        data.CopyTo(output);
        output[data.Length] = 0x80;
        return output;
    }

    public static byte[] Unpad(ReadOnlySpan<byte> data)
    {
        int i = data.Length - 1;
        while (i >= 0 && data[i] == 0x00) i--;
        if (i < 0 || data[i] != 0x80) throw new CryptographicException("Invalid ISO 9797-1 padding.");
        return data[..i].ToArray();
    }

    private static SymmetricAlgorithm Create(SmCipher cipher, byte[] key)
    {
        SymmetricAlgorithm algorithm = cipher == SmCipher.TripleDes ? TripleDES.Create() : Aes.Create();
        // Two-key 3DES: some platforms (macOS CommonCrypto) only accept the 24-byte K1 || K2 || K1 form.
        algorithm.Key = cipher == SmCipher.TripleDes && key.Length == 16 ? [.. key, .. key[..8]] : key;
        return algorithm;
    }
}
