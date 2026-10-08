using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Emrtd.Tests;

/// <summary>
/// Builds a synthetic eMRTD with a real CSCA → DSC → SOD chain: by default the ICAO 9303 Part 5 TD1 ID card
/// specimen, or any other MRZ such as the Part 4 TD3 passport specimen.
/// </summary>
internal sealed class TestDocument
{
    /// <summary>ICAO 9303 Part 5 specimen ID card (TD1, 3 × 30).</summary>
    public static readonly string[] MrzLines =
    [
        "I<UTOD231458907<<<<<<<<<<<<<<<",
        "7408122F1204159UTO<<<<<<<<<<<6",
        "ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
    ];

    /// <summary>ICAO 9303 Part 4 specimen passport (TD3, 2 × 44).</summary>
    public static readonly string[] PassportMrzLines =
    [
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
        "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
    ];

    public string[] Mrz { get; }
    public MrzKey Key { get; }
    public byte[] FaceJpeg { get; }
    public Dictionary<ushort, byte[]> Files { get; } = [];
    public Dictionary<int, byte[]> DataGroups { get; } = [];
    public X509Certificate Csca { get; }

    public TestDocument(string[]? mrzLines = null)
    {
        Mrz = mrzLines ?? MrzLines;
        Key = MrzKey.FromMrz(string.Join('\n', Mrz));

        // A fake JPEG large enough to need many READ BINARY chunks.
        FaceJpeg = [0xFF, 0xD8, 0xFF, 0xE0, .. Enumerable.Range(0, 5000).Select(i => (byte)(i * 7)), 0xFF, 0xD9];

        byte[] com = Tlv.Encode(0x60, [
            .. Tlv.Encode(0x5F01, "0107"u8), .. Tlv.Encode(0x5F36, "040000"u8), .. Tlv.Encode(0x5C, [0x61, 0x75, 0x6B])]);
        DataGroups[1] = Tlv.Encode(0x61, Tlv.Encode(0x5F1F, Encoding.ASCII.GetBytes(string.Concat(Mrz))));
        DataGroups[2] = Tlv.Encode(0x75, Tlv.Encode(0x7F61, [
            .. Tlv.Encode(0x02, [0x01]),
            .. Tlv.Encode(0x7F60, [
                .. Tlv.Encode(0xA1, Tlv.Encode(0x80, [0x01, 0x01])),
                .. Tlv.Encode(0x5F2E, [.. "FAC\0010\0"u8, .. new byte[38], .. FaceJpeg])])]));
        DataGroups[11] = Tlv.Encode(0x6B, [
            .. Tlv.Encode(0x5C, [0x5F, 0x0E, 0x5F, 0x2B]),
            .. Tlv.Encode(0x5F0E, Encoding.UTF8.GetBytes("إريكسون<<آنا<ماريا")),
            .. Tlv.Encode(0x5F2B, "19740812"u8)]);

        var (cscaKey, csca) = CreateCertificate("CN=Test CSCA,C=UT", null, null, isCa: true);
        var (dscKey, dsc) = CreateCertificate("CN=Test Document Signer,C=UT", "CN=Test CSCA,C=UT", cscaKey.Private, isCa: false);
        Csca = csca;

        Files[Lds.Com] = com;
        foreach (var (dg, data) in DataGroups) Files[Lds.DataGroupFileId(dg)] = data;
        Files[Lds.Sod] = CreateSod(dscKey.Private, dsc);
    }

    private byte[] CreateSod(AsymmetricKeyParameter signerKey, X509Certificate signer)
    {
        var hashes = DataGroups.OrderBy(d => d.Key).Select(d => (Asn1Encodable)new DerSequence(
            new DerInteger(d.Key), new DerOctetString(DigestUtilities.CalculateDigest("SHA-256", d.Value))));
        var ldsSecurityObject = new DerSequence(
            new DerInteger(0),
            new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1")),
            new DerSequence(hashes.ToArray()));

        var generator = new CmsSignedDataGenerator();
        generator.AddSigner(signerKey, signer, CmsSignedGenerator.DigestSha256);
        generator.AddCertificates(CollectionUtilities.CreateStore([signer]));
        var cms = generator.Generate("2.23.136.1.1.1", new CmsProcessableByteArray(ldsSecurityObject.GetEncoded()), true);
        return Tlv.Encode(0x77, cms.GetEncoded());
    }

    private static (AsymmetricCipherKeyPair, X509Certificate) CreateCertificate(
        string subject, string? issuer, AsymmetricKeyParameter? issuerKey, bool isCa)
    {
        var keyGenerator = new ECKeyPairGenerator();
        keyGenerator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        var keys = keyGenerator.GenerateKeyPair();

        var certificate = new X509V3CertificateGenerator();
        certificate.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue)));
        certificate.SetSubjectDN(new X509Name(subject));
        certificate.SetIssuerDN(new X509Name(issuer ?? subject));
        certificate.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certificate.SetNotAfter(DateTime.UtcNow.AddYears(10));
        certificate.SetPublicKey(keys.Public);
        certificate.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));
        return (keys, certificate.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", issuerKey ?? keys.Private)));
    }

    /// <summary>EF.CardAccess advertising one PACEInfo (version 2, standardized domain parameters).</summary>
    public static byte[] CardAccess(string paceOid, int parameterId) =>
        new DerSet(new DerSequence(new DerObjectIdentifier(paceOid), new DerInteger(2), new DerInteger(parameterId))).GetEncoded();
}

file static class SecObjectIdentifiers
{
    public static readonly DerObjectIdentifier SecP256r1 = Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1;
}
