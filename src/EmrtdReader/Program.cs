using Emrtd;

// Usage:
//   EmrtdReader --mrz "<line1>|<line2>|<line3>" [options]
//   EmrtdReader --doc D23145890 --dob 740812 --exp 120415 [options]
//   EmrtdReader --list-readers
// Options: --reader <name part>  --csca <file or folder>  --out <folder>  --bac  --no-face  --timeout <seconds>
string? mrz = null, doc = null, dob = null, exp = null, readerName = null, cscaPath = null, outDir = null;
bool forceBac = false, readFace = true;
int timeoutSeconds = 60;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--mrz": mrz = args[++i]; break;
        case "--doc": doc = args[++i]; break;
        case "--dob": dob = args[++i]; break;
        case "--exp": exp = args[++i]; break;
        case "--reader": readerName = args[++i]; break;
        case "--csca": cscaPath = args[++i]; break;
        case "--out": outDir = args[++i]; break;
        case "--bac": forceBac = true; break;
        case "--no-face": readFace = false; break;
        case "--timeout": timeoutSeconds = int.Parse(args[++i]); break;
        case "--list-readers":
            string[] readers = PcscTransport.ListReaders();
            Console.WriteLine(readers.Length == 0 ? "No PC/SC readers found." : string.Join(Environment.NewLine, readers));
            return 0;
        default:
            Console.Error.WriteLine($"Unknown argument: {args[i]}");
            return 1;
    }
}

MrzKey key;
try
{
    key = mrz is not null ? MrzKey.FromMrz(mrz)
        : doc is not null && dob is not null && exp is not null ? new MrzKey(doc, dob, exp)
        : throw new ArgumentException("Pass --mrz \"<line1>|<line2>|<line3>\" or --doc/--dob/--exp.");
}
catch (Exception ex) when (ex is ArgumentException or FormatException)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

CscaStore? trustStore = null;
if (cscaPath is not null)
{
    trustStore = CscaStore.Load(cscaPath);
    Console.WriteLine($"Loaded {trustStore.Certificates.Count} CSCA certificate(s) from {cscaPath}");
}

void Log(string message) => Console.WriteLine($"  · {message}");

EmrtdDocument document;
try
{
    using var transport = PcscTransport.WaitForCard(readerName, TimeSpan.FromSeconds(timeoutSeconds), Log);
    Log($"ATR: {Convert.ToHexString(transport.Atr)}");
    var started = DateTime.UtcNow;
    document = new DocumentReader(transport, Log).Read(key, new ReadOptions
    {
        UsePace = !forceBac,
        ReadFace = readFace,
        TrustStore = trustStore,
    });
    Log($"Read in {(DateTime.UtcNow - started).TotalSeconds:F1} s");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed: {ex.Message}");
    return 2;
}

Console.WriteLine();
Console.WriteLine($"Access control : {document.AccessControl}");
Console.WriteLine($"LDS version    : {document.LdsVersion}");
Console.WriteLine($"Data groups    : {string.Join(", ", document.DataGroupsPresent.Select(g => $"DG{g}"))}");
Console.WriteLine();
Console.WriteLine("MRZ (chip DG1):");
foreach (string line in document.Mrz) Console.WriteLine($"  {line}");

if (mrz is not null)
{
    string[] ocrLines = mrz.Split(['|', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    bool same = ocrLines.SequenceEqual(document.Mrz);
    Console.WriteLine($"  OCR MRZ vs chip: {(same ? "identical" : "DIFFERENT")}");
}

if (document.PersonalDetails.Count > 0)
{
    Console.WriteLine();
    Console.WriteLine("Personal details (DG11):");
    foreach (var (name, value) in document.PersonalDetails) Console.WriteLine($"  {name,-24}: {value}");
}
if (document.DocumentDetails.Count > 0)
{
    Console.WriteLine();
    Console.WriteLine("Document details (DG12):");
    foreach (var (name, value) in document.DocumentDetails) Console.WriteLine($"  {name,-24}: {value}");
}

if (document.Face is { } face)
{
    Console.WriteLine();
    Console.WriteLine($"Face image (DG2): {face.MimeType}, {face.Data.Length:N0} bytes");
}

if (outDir is not null)
{
    Directory.CreateDirectory(outDir);
    foreach (var (name, data) in document.RawFiles) File.WriteAllBytes(Path.Combine(outDir, $"{name}.bin"), data);
    if (document.Face is { } f) File.WriteAllBytes(Path.Combine(outDir, "face" + f.FileExtension), f.Data);
    Console.WriteLine($"Saved raw files{(document.Face is null ? "" : " and face image")} to {Path.GetFullPath(outDir)}");
}

Console.WriteLine();
if (document.PassiveAuthentication is not { } pa)
{
    Console.WriteLine("Passive authentication: EF.SOD not readable");
    return 3;
}

Console.WriteLine("Passive authentication:");
Console.WriteLine($"  Document signer : {pa.DocumentSigner}");
Console.WriteLine($"  Issued by       : {pa.DocumentSignerIssuer}");
Console.WriteLine($"  DSC valid until : {pa.DocumentSignerNotAfter:yyyy-MM-dd}");
Console.WriteLine($"  SOD signature   : {(pa.SignatureValid ? "OK" : "INVALID")}");
Console.WriteLine($"  CSCA trust      : {pa.ChainsToTrustedCsca switch { true => "OK", false => "NOT TRUSTED", null => "not checked (pass --csca)" }}");
Console.WriteLine($"  Hashes ({pa.HashAlgorithm}): {string.Join(", ", pa.DataGroups)}");
foreach (string error in pa.Errors) Console.WriteLine($"  ! {error}");
Console.WriteLine($"  Result          : {(pa.IsValid ? "GENUINE" : "NOT VERIFIED")}");

return pa.IsValid ? 0 : 3;
