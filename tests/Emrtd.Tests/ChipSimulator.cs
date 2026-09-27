using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace Emrtd.Tests;

/// <summary>
/// Card-side implementation of an eMRTD chip: BAC, PACE ECDH-GM and secure messaging, written
/// independently of the reader-side classes so the tests exercise both ends of the protocol.
/// </summary>
internal sealed class ChipSimulator : ICardTransport
{
    private readonly MrzKey _key;
    private readonly Dictionary<ushort, byte[]> _appletFiles;
    private readonly byte[]? _cardAccess;
    private readonly bool _allowBac;
    private readonly SecureRandom _random = new();

    private bool _appletSelected;
    private ushort? _selectedFile;
    private byte[]? _rndIc;
    private ChipSm? _sm;

    // PACE state
    private string? _paceOid;
    private X9ECParameters? _curve;
    private byte[]? _nonce;
    private BigInteger? _mapPrivate;
    private ECPoint? _mappedG;
    private ECPoint? _chipEphemeral, _terminalEphemeral;
    private byte[]? _paceKsEnc, _paceKsMac;
    private int _paceStep;

    public ChipSimulator(MrzKey key, Dictionary<ushort, byte[]> appletFiles, byte[]? cardAccess = null, bool allowBac = true)
    {
        _key = key;
        _appletFiles = appletFiles;
        _cardAccess = cardAccess;
        _allowBac = allowBac;
    }

    public List<string> Log { get; } = [];

    public byte[] Transmit(byte[] apdu)
    {
        try
        {
            if (_sm is not null && (apdu[0] & 0x0C) == 0x0C)
            {
                var (cla, ins, p1, p2, data, le) = _sm.UnwrapCommand(apdu);
                var (responseData, sw) = Process(cla, ins, p1, p2, data, le);
                return _sm.WrapResponse(responseData, sw);
            }
            var command = ParsePlain(apdu);
            var (plainData, plainSw) = Process(command.Cla, command.Ins, command.P1, command.P2, command.Data, command.Le);
            // Secure messaging starts after the authentication response has gone out in plain text.
            if (_pendingSm is not null)
            {
                _sm = _pendingSm;
                _pendingSm = null;
            }
            return [.. plainData, (byte)(plainSw >> 8), (byte)plainSw];
        }
        catch (ChipError e)
        {
            // A broken secure messaging session is reported in plain text and ends the session.
            _sm = null;
            return [(byte)(e.SW >> 8), (byte)e.SW];
        }
    }

    public void Reset()
    {
        _appletSelected = false;
        _selectedFile = null;
        _sm = null;
        _pendingSm = null;
        _paceStep = 0;
    }

    public void Dispose() { }

    private (byte[] Data, ushort SW) Process(byte cla, byte ins, byte p1, byte p2, byte[] data, int le)
    {
        Log.Add($"{ins:X2} {p1:X2}{p2:X2} {(_sm is null ? "plain" : "SM")}");
        switch (ins)
        {
            case 0xA4 when p1 == 0x04:
                if (!data.AsSpan().SequenceEqual(EmrtdSession.AppletAid)) return ([], 0x6A82);
                _appletSelected = true;
                _selectedFile = null;
                return ([], 0x9000);

            case 0xA4 when p1 == 0x02:
                return SelectFile((ushort)(data[0] << 8 | data[1]));

            case 0xB0:
                if ((p1 & 0x80) != 0)
                {
                    var select = SelectFile((ushort)(0x0100 | (p1 & 0x1F)));
                    if (select.SW != 0x9000) return select;
                    return ReadBinary(p2, le);
                }
                return ReadBinary(p1 << 8 | p2, le);

            case 0x84:
                if (!_allowBac) return ([], 0x6D00);
                _rndIc = RandomNumberGenerator.GetBytes(8);
                return (_rndIc, 0x9000);

            case 0x82:
                return BacMutualAuthenticate(data);

            case 0x22:
                return MseSetAt(data);

            case 0x86:
                return GeneralAuthenticate(data);

            default:
                return ([], 0x6D00);
        }
    }

    private (byte[] Data, ushort SW) SelectFile(ushort fid)
    {
        if (fid == Lds.CardAccess && _cardAccess is not null && !_appletSelected)
        {
            _selectedFile = fid;
            return ([], 0x9000);
        }
        if (!_appletSelected || !_appletFiles.ContainsKey(fid)) return ([], 0x6A82);
        if (_sm is null) return ([], 0x6982);
        _selectedFile = fid;
        return ([], 0x9000);
    }

    private (byte[], ushort) ReadBinary(int offset, int le)
    {
        if (_selectedFile is not ushort fid) return ([], 0x6986);
        byte[] file = fid == Lds.CardAccess && !_appletSelected ? _cardAccess! : _appletFiles[fid];
        if (offset >= file.Length) return ([], 0x6B00);
        int length = Math.Min(le, file.Length - offset);
        return (file[offset..(offset + length)], length < le ? (ushort)0x6282 : (ushort)0x9000);
    }

    private (byte[], ushort) BacMutualAuthenticate(byte[] data)
    {
        if (_rndIc is null || data.Length != 40) return ([], 0x6985);
        byte[] seed = _key.Hash()[..16];
        byte[] kEnc = Crypto.Kdf(seed, 1, SmCipher.TripleDes), kMac = Crypto.Kdf(seed, 2, SmCipher.TripleDes);

        if (!Crypto.Mac(SmCipher.TripleDes, kMac, Crypto.Pad(data[..32], 8)).AsSpan().SequenceEqual(data[32..]))
            return ([], 0x6300);
        byte[] s = Crypto.Decrypt(SmCipher.TripleDes, kEnc, data[..32], new byte[8]);
        byte[] rndIfd = s[..8], rndIc = s[8..16], kIfd = s[16..32];
        if (!rndIc.AsSpan().SequenceEqual(_rndIc)) return ([], 0x6300);

        byte[] kIc = RandomNumberGenerator.GetBytes(16);
        byte[] eIc = Crypto.Encrypt(SmCipher.TripleDes, kEnc, [.. rndIc, .. rndIfd, .. kIc], new byte[8]);
        byte[] mIc = Crypto.Mac(SmCipher.TripleDes, kMac, Crypto.Pad(eIc, 8));

        byte[] sessionSeed = kIfd.Zip(kIc, (a, b) => (byte)(a ^ b)).ToArray();
        _pendingSm = new ChipSm(SmCipher.TripleDes, Crypto.Kdf(sessionSeed, 1, SmCipher.TripleDes),
            Crypto.Kdf(sessionSeed, 2, SmCipher.TripleDes), [.. rndIc[4..], .. rndIfd[4..]]);
        return ([.. eIc, .. mIc], 0x9000);
    }

    private ChipSm? _pendingSm;

    private (byte[], ushort) MseSetAt(byte[] data)
    {
        var objects = Tlv.ParseAll(data).ToDictionary(t => t.Tag, t => t.Value);
        _paceOid = Org.BouncyCastle.Asn1.DerObjectIdentifier.GetInstance(Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(Tlv.Encode(0x06, objects[0x80]))).Id;
        _curve = ECNamedCurveTable.GetByName(Pace.CurveName(objects[0x84][0]));
        _paceStep = 1;
        return ([], 0x9000);
    }

    private (byte[], ushort) GeneralAuthenticate(byte[] data)
    {
        var info = new PaceInfo(_paceOid!, 2, null);
        var domain = new ECDomainParameters(_curve!);
        byte[] input = Tlv.Parse(data).Children.FirstOrDefault()?.Value ?? [];
        int blockSize = Crypto.BlockSize(info.Cipher);

        switch (_paceStep)
        {
            case 1:
            {
                _nonce = RandomNumberGenerator.GetBytes(blockSize);
                byte[] kPi = Crypto.Kdf(_key.Hash(), 3, info.Cipher);
                byte[] z = Crypto.Encrypt(info.Cipher, kPi, _nonce, new byte[blockSize]);
                _paceStep = 2;
                return (Tlv.Encode(0x7C, Tlv.Encode(0x80, z)), 0x9000);
            }
            case 2:
            {
                _mapPrivate = BigIntegers.CreateRandomInRange(BigInteger.One, domain.N.Subtract(BigInteger.One), _random);
                ECPoint terminalMap = _curve!.Curve.DecodePoint(input);
                ECPoint h = terminalMap.Multiply(_mapPrivate).Normalize();
                _mappedG = domain.G.Multiply(new BigInteger(1, _nonce)).Add(h).Normalize();
                _paceStep = 3;
                return (Tlv.Encode(0x7C, Tlv.Encode(0x82, domain.G.Multiply(_mapPrivate).Normalize().GetEncoded(false))), 0x9000);
            }
            case 3:
            {
                _terminalEphemeral = _curve!.Curve.DecodePoint(input).Normalize();
                BigInteger sk = BigIntegers.CreateRandomInRange(BigInteger.One, domain.N.Subtract(BigInteger.One), _random);
                _chipEphemeral = _mappedG!.Multiply(sk).Normalize();
                ECPoint shared = _terminalEphemeral.Multiply(sk).Normalize();
                byte[] k = BigIntegers.AsUnsignedByteArray((_curve.Curve.FieldSize + 7) / 8, shared.AffineXCoord.ToBigInteger());
                _paceKsEnc = Crypto.Kdf(k, 1, info.Cipher);
                _paceKsMac = Crypto.Kdf(k, 2, info.Cipher);
                _paceStep = 4;
                return (Tlv.Encode(0x7C, Tlv.Encode(0x84, _chipEphemeral.GetEncoded(false))), 0x9000);
            }
            case 4:
            {
                if (!input.AsSpan().SequenceEqual(Token(info, _paceKsMac!, _chipEphemeral!))) return ([], 0x6300);
                _paceStep = 0;
                _pendingSm = new ChipSm(info.Cipher, _paceKsEnc!, _paceKsMac!, new byte[blockSize]);
                return (Tlv.Encode(0x7C, Tlv.Encode(0x86, Token(info, _paceKsMac!, _terminalEphemeral!))), 0x9000);
            }
            default:
                return ([], 0x6985);
        }
    }

    // Built with BouncyCastle MACs directly, not with the reader's Pace.AuthenticationToken.
    private byte[] Token(PaceInfo info, byte[] ksMac, ECPoint point)
    {
        byte[] oid = new Org.BouncyCastle.Asn1.DerObjectIdentifier(info.Oid).GetEncoded();
        byte[] inner = [.. oid, .. Tlv.Encode(0x86, point.GetEncoded(false))];
        byte[] dataObject = [0x7F, 0x49, .. Tlv.EncodeLength(inner.Length), .. inner];

        Org.BouncyCastle.Crypto.IMac mac = info.Cipher == SmCipher.TripleDes
            ? new Org.BouncyCastle.Crypto.Macs.ISO9797Alg3Mac(new Org.BouncyCastle.Crypto.Engines.DesEngine(), new Org.BouncyCastle.Crypto.Paddings.ISO7816d4Padding())
            : new Org.BouncyCastle.Crypto.Macs.CMac(new Org.BouncyCastle.Crypto.Engines.AesEngine(), 64);
        mac.Init(new KeyParameter(ksMac));
        mac.BlockUpdate(dataObject);
        byte[] output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    private static (byte Cla, byte Ins, byte P1, byte P2, byte[] Data, int Le) ParsePlain(byte[] apdu)
    {
        if (apdu.Length == 4) return (apdu[0], apdu[1], apdu[2], apdu[3], [], 0);
        if (apdu.Length == 5) return (apdu[0], apdu[1], apdu[2], apdu[3], [], apdu[4] == 0 ? 256 : apdu[4]);
        int lc = apdu[4];
        byte[] data = apdu[5..(5 + lc)];
        int le = apdu.Length > 5 + lc ? (apdu[5 + lc] == 0 ? 256 : apdu[5 + lc]) : 0;
        return (apdu[0], apdu[1], apdu[2], apdu[3], data, le);
    }

    private sealed class ChipError(ushort sw) : Exception
    {
        public ushort SW { get; } = sw;
    }

    /// <summary>Card side of ICAO 9303 secure messaging.</summary>
    private sealed class ChipSm(SmCipher cipher, byte[] ksEnc, byte[] ksMac, byte[] ssc)
    {
        private readonly byte[] _ssc = (byte[])ssc.Clone();
        private int BlockSize => Crypto.BlockSize(cipher);

        public (byte Cla, byte Ins, byte P1, byte P2, byte[] Data, int Le) UnwrapCommand(byte[] apdu)
        {
            Increment();
            byte[] body = apdu[5..(5 + apdu[4])];
            byte[] macInput = [.. _ssc, .. Crypto.Pad(apdu[..4], BlockSize)];
            byte[]? encrypted = null, cc = null;
            int le = 0;
            foreach (var obj in Tlv.ParseAll(body))
            {
                if (obj.Tag == 0x87) { encrypted = obj.Value[1..]; macInput = [.. macInput, .. obj.Encode()]; }
                else if (obj.Tag == 0x97) { le = obj.Value[0] == 0 ? 256 : obj.Value[0]; macInput = [.. macInput, .. obj.Encode()]; }
                else if (obj.Tag == 0x8E) cc = obj.Value;
            }
            if (cc is null || !Crypto.Mac(cipher, ksMac, Crypto.Pad(macInput, BlockSize)).AsSpan().SequenceEqual(cc))
                throw new ChipError(0x6988);
            byte[] data = encrypted is null ? [] : Crypto.Unpad(Crypto.Decrypt(cipher, ksEnc, encrypted, Iv()));
            return ((byte)(apdu[0] & ~0x0C), apdu[1], apdu[2], apdu[3], data, le);
        }

        public byte[] WrapResponse(byte[] data, ushort sw)
        {
            Increment();
            byte[] do87 = data.Length == 0 ? [] : Tlv.Encode(0x87, [0x01, .. Crypto.Encrypt(cipher, ksEnc, Crypto.Pad(data, BlockSize), Iv())]);
            byte[] do99 = Tlv.Encode(0x99, [(byte)(sw >> 8), (byte)sw]);
            byte[] mac = Crypto.Mac(cipher, ksMac, Crypto.Pad([.. _ssc, .. do87, .. do99], BlockSize));
            return [.. do87, .. do99, .. Tlv.Encode(0x8E, mac), 0x90, 0x00];
        }

        private byte[] Iv() => cipher == SmCipher.TripleDes ? new byte[8] : Crypto.AesEcb(ksEnc, _ssc);

        private void Increment()
        {
            for (int i = _ssc.Length - 1; i >= 0; i--)
                if (++_ssc[i] != 0) break;
        }
    }
}
