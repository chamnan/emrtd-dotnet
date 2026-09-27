using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Emrtd;

public sealed record DataGroupHash(int DataGroup, bool? Matches)
{
    public override string ToString() => $"DG{DataGroup}: {Matches switch { true => "OK", false => "MISMATCH", null => "not read" }}";
}

public sealed record PassiveAuthenticationResult
{
    public required bool SignatureValid { get; init; }

    /// <summary>True if the DSC chains to a CSCA in the trust store; null when no trust store was supplied.</summary>
    public required bool? ChainsToTrustedCsca { get; init; }

    public required string HashAlgorithm { get; init; }
    public required IReadOnlyList<DataGroupHash> DataGroups { get; init; }
    public string? DocumentSigner { get; init; }
    public string? DocumentSignerIssuer { get; init; }
    public DateTime? DocumentSignerNotAfter { get; init; }
    public List<string> Errors { get; } = [];

    /// <summary>Signature OK, every data group that was read matches its signed hash, and the DSC chains to a trusted CSCA.</summary>
    public bool IsValid => SignatureValid && ChainsToTrustedCsca == true && DataGroups.All(d => d.Matches != false);
}

/// <summary>
/// Passive Authentication (ICAO 9303 Part 11 §5.1): verifies that EF.SOD is signed by the
/// Document Signer, that the DSC is issued by a trusted CSCA, and that each data group hash matches.
/// </summary>
public static class PassiveAuthentication
{
    internal static byte[] SignedContent(CmsSignedData cms)
    {
        using var stream = new MemoryStream();
        cms.SignedContent.Write(stream);
        return stream.ToArray();
    }

    public static PassiveAuthenticationResult Verify(byte[] sod, IReadOnlyDictionary<int, byte[]> dataGroups, CscaStore? trustStore)
    {
        // EF.SOD = 77 { ContentInfo (CMS SignedData) }, content = LDSSecurityObject.
        var cms = new CmsSignedData(Tlv.Parse(sod).Value);
        byte[] content = SignedContent(cms);
        var lds = Asn1Sequence.GetInstance(content);

        string hashOid = DerObjectIdentifier.GetInstance(Asn1Sequence.GetInstance(lds[1])[0]).Id;
        var signedHashes = Asn1Sequence.GetInstance(lds[2]).Cast<Asn1Encodable>()
            .Select(Asn1Sequence.GetInstance)
            .ToDictionary(s => DerInteger.GetInstance(s[0]).IntValueExact, s => Asn1OctetString.GetInstance(s[1]).GetOctets());

        var groups = signedHashes.Keys.Order()
            .Select(dg => new DataGroupHash(dg, dataGroups.TryGetValue(dg, out byte[]? data)
                ? DigestUtilities.CalculateDigest(hashOid, data).AsSpan().SequenceEqual(signedHashes[dg])
                : null))
            .ToList();

        var errors = new List<string>();
        foreach (int unexpected in dataGroups.Keys.Except(signedHashes.Keys))
            errors.Add($"DG{unexpected} was read but is not covered by the SOD.");

        SignerInformation signer = cms.GetSignerInfos().GetSigners().Cast<SignerInformation>().First();
        X509Certificate? dsc = cms.GetCertificates().EnumerateMatches(signer.SignerID).FirstOrDefault();

        bool signatureValid = false;
        if (dsc is null)
        {
            errors.Add("SOD does not embed the Document Signer certificate.");
        }
        else
        {
            try
            {
                signatureValid = signer.Verify(dsc);
            }
            catch (Exception ex) when (ex is CmsException or InvalidOperationException or ArgumentException)
            {
                errors.Add($"SOD signature verification error: {ex.Message}");
            }
            if (!signatureValid) errors.Add("SOD signature is invalid.");
        }

        bool? trusted = null;
        if (trustStore is not null && dsc is not null)
        {
            trusted = trustStore.IsIssuedByTrustedCsca(dsc, out string? reason);
            if (!trusted.Value) errors.Add(reason ?? "Document Signer is not issued by a trusted CSCA.");
        }

        var result = new PassiveAuthenticationResult
        {
            SignatureValid = signatureValid,
            ChainsToTrustedCsca = trusted,
            HashAlgorithm = DigestUtilities.GetAlgorithmName(new DerObjectIdentifier(hashOid)) ?? hashOid,
            DataGroups = groups,
            DocumentSigner = dsc?.SubjectDN.ToString(),
            DocumentSignerIssuer = dsc?.IssuerDN.ToString(),
            DocumentSignerNotAfter = dsc?.NotAfter,
        };
        result.Errors.AddRange(errors);
        return result;
    }
}

/// <summary>
/// Trusted Country Signing CA certificates. Loads DER/PEM certificates and ICAO master lists (.ml),
/// e.g. the German BSI master list or certificates obtained from the issuing state / ICAO PKD.
/// </summary>
public sealed class CscaStore
{
    private readonly List<X509Certificate> _certificates = [];

    public IReadOnlyList<X509Certificate> Certificates => _certificates;

    public static CscaStore Load(string path)
    {
        var store = new CscaStore();
        IEnumerable<string> files = Directory.Exists(path)
            ? Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
            : [path];

        foreach (string file in files)
        {
            switch (Path.GetExtension(file).ToLowerInvariant())
            {
                case ".ml":
                    store.AddMasterList(File.ReadAllBytes(file));
                    break;
                case ".cer" or ".crt" or ".der" or ".pem":
                    store._certificates.AddRange(new X509CertificateParser().ReadCertificates(File.ReadAllBytes(file)).Cast<X509Certificate>());
                    break;
            }
        }
        return store;
    }

    public void Add(X509Certificate certificate) => _certificates.Add(certificate);

    /// <summary>ICAO master list: CMS SignedData whose content is CscaMasterList ::= SEQUENCE { version, SET OF Certificate }.</summary>
    public void AddMasterList(byte[] masterList)
    {
        var cms = new CmsSignedData(masterList);
        var list = Asn1Sequence.GetInstance(PassiveAuthentication.SignedContent(cms));
        foreach (Asn1Encodable cert in Asn1Set.GetInstance(list[1]))
            _certificates.Add(new X509Certificate(Org.BouncyCastle.Asn1.X509.X509CertificateStructure.GetInstance(cert)));
    }

    public bool IsIssuedByTrustedCsca(X509Certificate dsc, out string? reason)
    {
        var candidates = _certificates.Where(c => c.SubjectDN.Equivalent(dsc.IssuerDN)).ToList();
        if (candidates.Count == 0)
        {
            reason = $"No CSCA in the trust store matches the DSC issuer '{dsc.IssuerDN}'.";
            return false;
        }

        foreach (var csca in candidates)
        {
            try
            {
                dsc.Verify(csca.GetPublicKey());
                reason = null;
                return true;
            }
            catch (GeneralSecurityException)
            {
                // Same name, different key (e.g. a CSCA rollover): try the next one.
            }
        }
        reason = "The DSC signature does not verify with any CSCA whose name matches its issuer.";
        return false;
    }
}
