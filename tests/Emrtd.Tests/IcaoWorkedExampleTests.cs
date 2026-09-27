using static System.Convert;

namespace Emrtd.Tests;

/// <summary>Vectors from ICAO Doc 9303 Part 11, Appendix D (BAC and secure messaging worked example).</summary>
public class IcaoWorkedExampleTests
{
    private static readonly MrzKey Key = new("L898902C", "690806", "940623");

    [Fact]
    public void MrzInformation_IncludesCheckDigits()
    {
        Assert.Equal("L898902C<369080619406236", Key.MrzInformation);
    }

    [Fact]
    public void BacKeys_AreDerivedFromMrz()
    {
        byte[] seed = Key.Hash()[..16];
        Assert.Equal("239AB9CB282DAF66231DC5A4DF6BFBAE", ToHexString(seed));
        Assert.Equal("AB94FDECF2674FDFB9B391F85D7F76F2", ToHexString(Crypto.Kdf(seed, Crypto.KdfEnc, SmCipher.TripleDes)));
        Assert.Equal("7962D9ECE03D1ACD4C76089DCE131543", ToHexString(Crypto.Kdf(seed, Crypto.KdfMac, SmCipher.TripleDes)));
    }

    [Fact]
    public void Bac_ProducesSessionKeysAndSsc()
    {
        var transport = new ScriptedTransport(
            ("0084000008", "4608F919887022129000"),
            ("008200002872C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A728",
             "46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D74499000"));

        var sm = Bac.Authenticate(new EmrtdSession(transport), Key,
            FromHexString("781723860C06C226"), FromHexString("0B795240CB7049B01C19B33E32804F0B"));

        Assert.Equal("887022120C06C226", ToHexString(sm.Ssc));
        transport.AssertDone();
    }

    [Fact]
    public void SecureMessaging_MatchesWorkedExample()
    {
        var sm = new SecureMessaging(SmCipher.TripleDes,
            FromHexString("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            FromHexString("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            FromHexString("887022120C06C226"));

        // SELECT EF.COM
        Assert.Equal("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800",
            ToHexString(sm.Wrap(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, [0x01, 0x1E]))));
        Assert.Equal(0x9000, sm.Unwrap(FromHexString("990290008E08FA855A5D4C50A8ED9000")).SW);

        // READ BINARY, first 4 bytes
        Assert.Equal("0CB000000D9701048E08ED6705417E96BA5500",
            ToHexString(sm.Wrap(new CommandApdu(0x00, 0xB0, 0x00, 0x00, Ne: 4))));
        var header = sm.Unwrap(FromHexString("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000"));
        Assert.Equal("60145F01", ToHexString(header.Data));

        // READ BINARY, remaining 18 bytes from offset 4
        Assert.Equal("0CB000040D9701128E082EA28A70F3C7B53500",
            ToHexString(sm.Wrap(new CommandApdu(0x00, 0xB0, 0x00, 0x04, Ne: 18))));
        var rest = sm.Unwrap(FromHexString(
            "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000"));
        Assert.Equal("04303130365F36063034303030305C026175", ToHexString(rest.Data));
    }

    [Fact]
    public void SecureMessaging_RejectsTamperedResponse()
    {
        var sm = new SecureMessaging(SmCipher.TripleDes,
            FromHexString("979EC13B1CBFE9DCD01AB0FED307EAE5"),
            FromHexString("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            FromHexString("887022120C06C226"));
        sm.Wrap(new CommandApdu(0x00, 0xA4, 0x02, 0x0C, [0x01, 0x1E]));

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => sm.Unwrap(FromHexString("990290008E08FA855A5D4C50A8EE9000")));
    }
}

/// <summary>ICAO Doc 9303 Part 11, Appendix G.1: PACE ECDH generic mapping, AES-128, brainpoolP256r1.</summary>
public class IcaoPaceWorkedExampleTests
{
    [Fact]
    public void Pace_EcdhGenericMapping_MatchesWorkedExample()
    {
        var key = new MrzKey("T22000129", "640812", "101031");
        Assert.Equal("T22000129364081251010318", key.MrzInformation);

        var transport = new ScriptedTransport(
            // MSE:Set AT (the worked example omits 84; we always send the standardized parameter id)
            ("0022C1A412800A04007F0007020204020283010184010D", "9000"),
            ("10860000027C0000", "7C12801095A3A016522EE98D01E76CB6B98B42C39000"),
            ("10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D00",
             "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C549000"),
            ("10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462" + "00",
             "7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F0949000"),
            ("008600000C7C0A8508C2B0BD78D94BA86600", "7C0A86083ABB9674BCE93C089000"));

        var info = new PaceInfo("0.4.0.127.0.7.2.2.4.2.2", 2, 13);
        var sm = Pace.Authenticate(new EmrtdSession(transport), key, info,
            _ => new Org.BouncyCastle.Math.BigInteger("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99", 16),
            _ => new Org.BouncyCastle.Math.BigInteger("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595", 16));

        Assert.Equal(SmCipher.Aes128, sm.Cipher);
        Assert.Equal(new byte[16], sm.Ssc);
        transport.AssertDone();
    }
}

/// <summary>Replays fixed responses and asserts the exact commands sent.</summary>
internal sealed class ScriptedTransport(params (string Command, string Response)[] script) : ICardTransport
{
    private int _next;

    public byte[] Transmit(byte[] apdu)
    {
        Assert.True(_next < script.Length, $"Unexpected extra command {ToHexString(apdu)}");
        var (command, response) = script[_next++];
        Assert.Equal(command, ToHexString(apdu));
        return FromHexString(response);
    }

    public void AssertDone() => Assert.Equal(script.Length, _next);

    public void Reset() { }

    public void Dispose() { }
}
