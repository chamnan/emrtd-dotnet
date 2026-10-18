# Emrtd

Reads the chip of ICAO 9303 identity documents (ePassports and eID cards) over PC/SC, using the MRZ as the
access key, and verifies it with Passive Authentication.

- PACE v2 (ECDH generic mapping, 3DES / AES-128 / 192 / 256, standardized curves), with fallback to BAC
- Secure messaging (3DES and AES)
- LDS parsing: COM, DG1 (MRZ), DG2 (face, JPEG / JPEG 2000), DG11, DG12, SOD; other data groups as raw bytes
- Passive Authentication: SOD signature, data group hashes, Document Signer → CSCA (certificates or ICAO master lists)
- Offline parsing of chip dumps, no reader needed

Works with the built-in NFC reader of Windows devices (e.g. Microsoft Surface) and USB CCID readers
(ACS ACR1252U, HID Omnikey 5022, Identiv uTrust 3700F, ...). Also runs on macOS and Linux (pcsc-lite).

## Read a document

```csharp
using Emrtd;

var key = MrzKey.FromMrz("P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<|L898902C36UTO7408122F1204159ZE184226B<<<<<10");
// or: new MrzKey("L898902C3", "740812", "120415")

using var transport = PcscTransport.WaitForCard(readerName: null, TimeSpan.FromSeconds(60));
var document = new DocumentReader(transport, log: Console.WriteLine)
    .Read(key, new ReadOptions { TrustStore = CscaStore.Load("csca") });

Console.WriteLine(string.Join("\n", document.Mrz));
Console.WriteLine(document.AccessControl);                  // e.g. "PACE-ECDH-GM-Aes128 (brainpoolP256r1)" or "BAC (3DES)"
Console.WriteLine(document.PassiveAuthentication?.IsValid); // true = genuine
if (document.Face is { } face) File.WriteAllBytes("face" + face.FileExtension, face.Data);
```

## Parse a chip dump offline

```csharp
var files = DocumentReader.LoadDump("chip-dump");   // COM.bin, DG1.bin, ..., SOD.bin (any file names)
var document = DocumentReader.Parse(files, trustStore: CscaStore.Load("csca.cer"));
```

## Names: `<` and `<<`

DG11 names keep the MRZ notation: `<<` separates the primary identifier (surname) from the secondary identifier
(given names), `<` separates words. `Lds.SplitNameRaw` returns the parts as stored, `Lds.SplitName` with spaces.

```csharp
Lds.SplitNameRaw("ERIKSSON<<ANNA<MARIA"); // ("ERIKSSON", "ANNA<MARIA")
Lds.SplitName("ERIKSSON<<ANNA<MARIA");    // ("ERIKSSON", "ANNA MARIA")
```

## Not supported yet

PACE integrated mapping and DH (non-EC) PACE (falls back to BAC), Chip Authentication (DG14) and
Active Authentication (DG15) verification, EAC / Terminal Authentication (DG3 fingerprints, DG4 iris).

This is an early release. It has been verified against the ICAO worked examples and a simulated chip,
but not yet against a wide range of real documents.

Documentation: https://github.com/chamnan/emrtd-dotnet/wiki ·
Source and console tools: https://github.com/chamnan/emrtd-dotnet
