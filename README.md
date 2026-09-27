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

# MRZ reader (OCR)

```
dotnet run --project src/MrzReader -- <image> [--lang ocrb|eng] [--tessdata <dir>] [--debug]
```

It prints the MRZ lines, the parsed fields, the check digit results, and the MRZ as one `|`-separated string
that can be passed to `EmrtdReader --mrz`. Exit code: `0` = all check digits OK, `2` = no MRZ found, `3` = MRZ found but some check digits failed.

No sample images are included in this repository; use a photo of your own document or a specimen.

## Requirements

The Tesseract 5 native library must be installed (it is called through P/Invoke):

- **Windows**: install from https://github.com/UB-Mannheim/tesseract/wiki (default path `C:\Program Files\Tesseract-OCR` is probed automatically)
- **macOS**: `brew install tesseract`
- **Linux**: `apt install libtesseract5`

If the library is somewhere else, set `TESSERACT_LIB` to its full path.

Language models live in `src/MrzReader/tessdata` and are copied to the output folder. The stock `eng.traineddata`
(Apache-2.0, from https://github.com/tesseract-ocr/tessdata) is included. For much better accuracy, download the OCR-B model
(the MRZ font) from https://github.com/Shreeshrii/tessdata_ocrb. It is not redistributed here because that repository has no license:

```
curl -L -o src/MrzReader/tessdata/ocrb.traineddata https://github.com/Shreeshrii/tessdata_ocrb/raw/master/ocrb.traineddata
```

When `ocrb.traineddata` is missing, the app falls back to `eng`.

## How it works

1. `ImagePreprocessor`: crops the bottom of the image, upscales it and converts it to grayscale (SkiaSharp), optionally with an Otsu threshold.
2. `Tesseract`: runs OCR with a `A-Z0-9<` whitelist.
3. `MrzParser`: finds the MRZ lines, fixes line lengths and common OCR confusions (O/0, I/1, S/5, ...), then parses the fields and checks the check digits.

Several crop and scale variants are tried, and the result that passes the most check digits wins.

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
```

Other options: `--reader <part of name>`, `--bac` (skip PACE), `--no-face`, `--timeout <seconds>`.
Exit code: `0` = genuine (Passive Authentication passed), `2` = read failed, `3` = read but not verified.

`--csca` takes DER/PEM certificates or ICAO master lists (`.ml`), a single file or a folder. Without it,
the SOD signature and hashes are still checked, but not whether the Document Signer is trusted.

Publish for the Surface: `dotnet publish src/EmrtdReader -c Release -r win-x64` (or `win-arm64` for Snapdragon models).

## Tests

```
dotnet test tests/Emrtd.Tests
```

- ICAO 9303 Part 11 Appendix D (BAC key derivation, mutual authentication, secure messaging APDUs) and
  Appendix G.1 (PACE ECDH-GM AES-128 on brainpoolP256r1), matched byte for byte.
- A simulated chip (`ChipSimulator`) for end-to-end reads over BAC and five PACE variants, PACE→BAC
  fallback, wrong MRZ, a tampered data group and an untrusted CSCA.
