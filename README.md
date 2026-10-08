# emrtd-dotnet

Read ICAO 9303 identity documents (ePassports and eID cards) in .NET 10:

1. **MRZ OCR** (`src/MrzReader`): reads the machine readable zone from a photo of the document with Tesseract,
   and validates it with the check digits.
2. **NFC chip reading** (`src/Emrtd`, `src/EmrtdReader`): uses the MRZ as the access key (PACE or BAC),
   reads the chip over PC/SC, and verifies it with Passive Authentication.

Built as a proof of concept for a Windows (Microsoft Surface) eKYC app. The NFC code has been verified against
the ICAO worked examples and a simulated chip, but not yet against a wide range of real documents.

| Project | What it is |
|---|---|
| `src/MrzReader` | Console app: image → MRZ (TD1 / TD2 / TD3) |
| `src/Emrtd` | Class library: eMRTD chip access (PACE, BAC, secure messaging, LDS parsing, Passive Authentication) |
| `src/EmrtdReader` | Console app: MRZ → chip read on a PC/SC reader |
| `tests/Emrtd.Tests` | xUnit tests for the chip library |

Typical flow: photograph the MRZ side, run `MrzReader`, and pass its one-line MRZ string to `EmrtdReader --mrz`
while the document is on the NFC reader.

# MRZ reader (OCR)

```
dotnet run --project src/MrzReader -- <image> [--lang auto|ocrbfast|ocrb|eng] [--tessdata <dir>] [--debug]
```

It prints the MRZ lines, the parsed fields, the check digit results, and the MRZ as one `|`-separated string
that can be passed to `EmrtdReader --mrz`. Exit code: `0` = all check digits OK, `2` = no MRZ found, `3` = MRZ found but some check digits failed.

`image/` contains a specimen Iraqi national ID card (placeholder data, name CITIZEN JOHN):

```
dotnet run --project src/MrzReader -- image/docBack.jpg
```

The OCR reads the MRZ exactly, but the document number and composite check digits report FAILED: the
specimen's printed check digits are not valid, so it doubles as a negative test.

## Requirements

The Tesseract 5 native library must be installed (it is called through P/Invoke):

- **Windows**: install from https://github.com/UB-Mannheim/tesseract/wiki (default path `C:\Program Files\Tesseract-OCR` is probed automatically)
- **macOS**: `brew install tesseract`
- **Linux**: `apt install libtesseract5`

If the library is somewhere else, set `TESSERACT_LIB` to its full path.

On Snapdragon (ARM64) Surface models, the UB Mannheim builds are x64 only, so publish `MrzReader` for `win-x64`
(it runs under emulation). The NFC projects have no native dependencies and run natively on `win-arm64`.

Language models live in `src/MrzReader/tessdata` and are copied to the output folder. The stock `eng.traineddata`
(Apache-2.0, from https://github.com/tesseract-ocr/tessdata) is included. For much better accuracy, download the OCR-B model
(the MRZ font) from https://github.com/Shreeshrii/tessdata_ocrb. It is not redistributed here because that repository has no license:

```
curl -L -o src/MrzReader/tessdata/ocrb.traineddata https://github.com/Shreeshrii/tessdata_ocrb/raw/master/ocrb.traineddata
```

Optionally convert it to an integer model, which is about 30% faster per pass with the same results on the samples.
The file is platform independent, so it can be converted once on any machine with the Tesseract training tools:

```
combine_tessdata -e src/MrzReader/tessdata/ocrb.traineddata ocrb.lstm
lstmtraining --stop_training --convert_to_int --continue_from ocrb.lstm \
  --traineddata src/MrzReader/tessdata/ocrb.traineddata --model_output src/MrzReader/tessdata/ocrbfast.traineddata
```

With `--lang auto` (the default) the app uses `ocrbfast`, then `ocrb`, then falls back to `eng`.

## How it works

1. `ImagePreprocessor`: crops the bottom of the image, upscales it and converts it to grayscale (SkiaSharp), optionally with an Otsu threshold.
2. `Tesseract`: runs OCR with a `A-Z0-9<` whitelist.
3. `MrzParser`: finds the MRZ lines, fixes line lengths and common OCR confusions (O/0, I/1, S/5, ...), then parses the fields and checks the check digits.

Several crop and scale variants are tried, cheapest first, up to 4 at a time in parallel (one Tesseract engine per core pair).
Candidates are ranked by valid check digits, then by how few digit/letter corrections they needed (all-zero text passes
check digits trivially). The search stops when every check digit passes, or when two variants agree on the same MRZ.
`--debug` prints the OCR text, score and time of every variant.

Typical timing on an Apple M3 Max: 0.2–0.3 s of OCR, about 0.3–0.5 s for the whole process (0.5 s with one worker).
Slower CPUs and x64 emulation on ARM64 will add to this; run with `--debug` on the target device to see the
`OCR total`. In a long-running app, create the Tesseract engines once and reuse them across images.

# eMRTD chip reader (NFC)

`src/Emrtd` is a class library that reads the chip of ICAO 9303 documents (ePassports and eID cards)
over PC/SC, using the MRZ as the access key. JMRTD was used as the reference implementation.

| Feature | Status |
|---|---|
| PACE v2, ECDH generic mapping, 3DES / AES-128 / 192 / 256, standardized curves (param id 8–18) | ✅ |
| PACE chip authentication mapping (CAM) | key agreement only; the CAM data is not verified |
| PACE integrated mapping, DH (non-EC) PACE | ❌ falls back to BAC |
| BAC + 3DES secure messaging | ✅ |
| AES secure messaging | ✅ |
| Reading COM, DG1 (MRZ), DG2 (face, JPEG / JPEG 2000), DG11, DG12, other DGs, SOD | ✅ (files up to 32 KB) |
| Passive Authentication: SOD signature, DG hashes, DSC → CSCA | ✅ |
| Chip Authentication (DG14) / Active Authentication (DG15) | ❌ files are read, not verified yet |
| EAC / Terminal Authentication (DG3 fingerprints, DG4 iris) | ❌ needs certificates from the issuing state |

`src/EmrtdReader` is a console harness:

```
dotnet run --project src/EmrtdReader -- --list-readers
dotnet run --project src/EmrtdReader -- --mrz "<line1>|<line2>|<line3>" --csca <file-or-folder> --out chip-dump
dotnet run --project src/EmrtdReader -- --doc D23145890 --dob 740812 --exp 120415
dotnet run --project src/EmrtdReader -- --dump samples/icao-specimen-dump --csca samples/icao-specimen-dump/csca.cer
```

The last command reads the sample chip dump offline, with no reader needed (see [Offline: reading a chip dump](#offline-reading-a-chip-dump)).

Other options: `--reader <part of name>`, `--bac` (skip PACE), `--no-face`, `--timeout <seconds>`.
Exit code: `0` = genuine (Passive Authentication passed), `2` = read failed, `3` = read but not verified.

`--csca` takes DER/PEM certificates or ICAO master lists (`.ml`), a single file or a folder. Without it,
the SOD signature and hashes are still checked, but not whether the Document Signer is trusted.

### Offline: reading a chip dump

`--out` saves the raw chip files (`COM.bin`, `DG1.bin`, ..., `SOD.bin`). `--dump <folder>` parses such a folder
without a reader and runs Passive Authentication on it. Files are recognised by their LDS tag, not their name,
so dumps from other tools (`EF_COM.bin`, `0101.bin`, ...) work too.

`samples/icao-specimen-dump` is the ICAO 9303 Part 5 TD1 specimen (ANNA MARIA ERIKSSON) as a chip dump, signed by a
test CSCA (`csca.cer`, in the same folder):

```
dotnet run --project src/EmrtdReader -- --dump samples/icao-specimen-dump --csca samples/icao-specimen-dump/csca.cer
```

From code:

```csharp
var files = DocumentReader.LoadDump("samples/icao-specimen-dump");
var document = DocumentReader.Parse(files, trustStore: CscaStore.Load("samples/icao-specimen-dump/csca.cer"));
Console.WriteLine(string.Join("\n", document.Mrz));
Console.WriteLine(document.PassiveAuthentication?.IsValid);
```

Publish for the Surface: `dotnet publish src/EmrtdReader -c Release -r win-x64` (or `win-arm64` for Snapdragon models).

## Tests

```
dotnet test tests/Emrtd.Tests
```

- ICAO 9303 Part 11 Appendix D (BAC key derivation, mutual authentication, secure messaging APDUs) and
  Appendix G.1 (PACE ECDH-GM AES-128 on brainpoolP256r1), matched byte for byte.
- A simulated chip (`ChipSimulator`) for end-to-end reads over BAC and five PACE variants, PACE→BAC
  fallback, wrong MRZ, a tampered data group and an untrusted CSCA.
