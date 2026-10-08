namespace Emrtd.Tests;

public class DocumentReaderTests
{
    private readonly TestDocument _document = new();

    private CscaStore TrustStore()
    {
        var store = new CscaStore();
        store.Add(_document.Csca);
        return store;
    }

    [Fact]
    public void MrzKey_FromTd1_UsesDocumentNumberAndDates()
    {
        var key = MrzKey.FromMrz(string.Join('|', TestDocument.MrzLines));
        Assert.Equal("D23145890", key.DocumentNumber);
        Assert.Equal("740812", key.DateOfBirth);
        Assert.Equal("120415", key.DateOfExpiry);
        Assert.Equal("D23145890774081221204159", key.MrzInformation);
    }

    [Fact]
    public void MrzKey_FromTd3_UsesSecondLine()
    {
        var key = MrzKey.FromMrz(string.Join('|', TestDocument.PassportMrzLines));
        Assert.Equal("L898902C3", key.DocumentNumber);
        Assert.Equal("740812", key.DateOfBirth);
        Assert.Equal("120415", key.DateOfExpiry);
        Assert.Equal("L898902C3674081221204159", key.MrzInformation);
    }

    [Fact]
    public void Passport_Td3_IsReadOverPaceAndBac()
    {
        var passport = new TestDocument(TestDocument.PassportMrzLines);
        var store = new CscaStore();
        store.Add(passport.Csca);

        var bacChip = new ChipSimulator(passport.Key, passport.Files);
        AssertDocument(new DocumentReader(bacChip).Read(passport.Key, new ReadOptions { TrustStore = store }), passport.Mrz);

        var paceChip = new ChipSimulator(passport.Key, passport.Files, TestDocument.CardAccess("0.4.0.127.0.7.2.2.4.2.2", 13), allowBac: false);
        var result = new DocumentReader(paceChip).Read(passport.Key, new ReadOptions { TrustStore = store });
        Assert.StartsWith("PACE", result.AccessControl);
        AssertDocument(result, passport.Mrz);
    }

    [Fact]
    public void Bac_ReadsDocumentAndPassesPassiveAuthentication()
    {
        var chip = new ChipSimulator(_document.Key, _document.Files);
        var result = new DocumentReader(chip).Read(_document.Key, new ReadOptions { TrustStore = TrustStore() });

        Assert.Equal("BAC (3DES)", result.AccessControl);
        AssertDocument(result);
    }

    [Theory]
    [InlineData("0.4.0.127.0.7.2.2.4.2.2", 13, SmCipher.Aes128)]  // ECDH-GM AES-128 brainpoolP256r1
    [InlineData("0.4.0.127.0.7.2.2.4.2.2", 12, SmCipher.Aes128)]  // ECDH-GM AES-128 NIST P-256
    [InlineData("0.4.0.127.0.7.2.2.4.2.3", 16, SmCipher.Aes192)]  // ECDH-GM AES-192 brainpoolP384r1
    [InlineData("0.4.0.127.0.7.2.2.4.2.4", 15, SmCipher.Aes256)]  // ECDH-GM AES-256 NIST P-384
    [InlineData("0.4.0.127.0.7.2.2.4.2.1", 13, SmCipher.TripleDes)] // ECDH-GM 3DES brainpoolP256r1
    public void Pace_ReadsDocumentWithoutBac(string oid, int parameterId, SmCipher cipher)
    {
        var chip = new ChipSimulator(_document.Key, _document.Files, TestDocument.CardAccess(oid, parameterId), allowBac: false);
        var result = new DocumentReader(chip).Read(_document.Key, new ReadOptions { TrustStore = TrustStore() });

        Assert.StartsWith($"PACE-ECDH-GM-{cipher}", result.AccessControl);
        AssertDocument(result);
    }

    [Fact]
    public void Pace_FallsBackToBac_WhenVariantUnsupported()
    {
        // ECDH integrated mapping is not implemented, so the reader must use BAC.
        var chip = new ChipSimulator(_document.Key, _document.Files, TestDocument.CardAccess("0.4.0.127.0.7.2.2.4.4.2", 13));
        var result = new DocumentReader(chip).Read(_document.Key);

        Assert.Equal("BAC (3DES)", result.AccessControl);
    }

    [Fact]
    public void WrongMrz_IsRejected()
    {
        var wrongKey = new MrzKey("D23145890", "740812", "120416");
        var bacChip = new ChipSimulator(_document.Key, _document.Files);
        Assert.Equal(0x6300, Assert.Throws<CardException>(() => new DocumentReader(bacChip).Read(wrongKey)).SW);

        var paceChip = new ChipSimulator(_document.Key, _document.Files,
            TestDocument.CardAccess("0.4.0.127.0.7.2.2.4.2.2", 13), allowBac: false);
        Assert.ThrowsAny<Exception>(() => new DocumentReader(paceChip).Read(wrongKey));
    }

    [Fact]
    public void PassiveAuthentication_DetectsModifiedDataGroup()
    {
        var files = new Dictionary<ushort, byte[]>(_document.Files);
        byte[] dg1 = (byte[])files[Lds.DataGroupFileId(1)].Clone();
        dg1[^5] = (byte)'X'; // change a filler in the MRZ
        files[Lds.DataGroupFileId(1)] = dg1;

        var result = new DocumentReader(new ChipSimulator(_document.Key, files))
            .Read(_document.Key, new ReadOptions { TrustStore = TrustStore() });

        var pa = result.PassiveAuthentication!;
        Assert.True(pa.SignatureValid);
        Assert.False(pa.IsValid);
        Assert.Contains(pa.DataGroups, d => d is { DataGroup: 1, Matches: false });
    }

    [Fact]
    public void PassiveAuthentication_RejectsUnknownCsca()
    {
        var otherCsca = new TestDocument().Csca; // same name, different key
        var store = new CscaStore();
        store.Add(otherCsca);

        var result = new DocumentReader(new ChipSimulator(_document.Key, _document.Files))
            .Read(_document.Key, new ReadOptions { TrustStore = store });

        Assert.False(result.PassiveAuthentication!.ChainsToTrustedCsca);
        Assert.False(result.PassiveAuthentication.IsValid);
    }

    [Fact]
    public void Dump_IsParsedOffline_WhateverTheFileNames()
    {
        string folder = Directory.CreateTempSubdirectory().FullName;
        try
        {
            // Names as other tools write them; the files are recognised by their LDS tag.
            foreach (var (fileId, data) in _document.Files) File.WriteAllBytes(Path.Combine(folder, $"{fileId:X4}.bin"), data);
            File.WriteAllBytes(Path.Combine(folder, "csca.cer"), _document.Csca.GetEncoded());

            var files = DocumentReader.LoadDump(folder);
            Assert.Equal(["COM", "DG1", "DG11", "DG2", "SOD"], files.Keys.Order());

            var result = DocumentReader.Parse(files, trustStore: CscaStore.Load(Path.Combine(folder, "csca.cer")));
            AssertDocument(result);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private void AssertDocument(EmrtdDocument result, string[]? mrz = null)
    {
        Assert.Equal("0107", result.LdsVersion);
        Assert.Equal([1, 2, 11], result.DataGroupsPresent);
        Assert.Equal(mrz ?? TestDocument.MrzLines, result.Mrz);
        Assert.Equal(_document.FaceJpeg, result.Face!.Data);
        Assert.Equal("image/jpeg", result.Face.MimeType);
        Assert.Equal("إريكسون  آنا ماريا", result.PersonalDetails["Full name"]);
        Assert.Equal("إريكسون", result.PersonalDetails["Primary identifier"]);
        Assert.Equal("آنا ماريا", result.PersonalDetails["Secondary identifier"]);
        Assert.Equal("19740812", result.PersonalDetails["Full date of birth"]);

        var pa = result.PassiveAuthentication!;
        Assert.True(pa.SignatureValid, string.Join("; ", pa.Errors));
        Assert.True(pa.ChainsToTrustedCsca, string.Join("; ", pa.Errors));
        Assert.All(pa.DataGroups, d => Assert.True(d.Matches));
        Assert.True(pa.IsValid);
    }
}
