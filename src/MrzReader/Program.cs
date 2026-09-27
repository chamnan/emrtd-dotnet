using MrzReader;
using SkiaSharp;

// Usage: MrzReader [image] [--lang ocrb|eng] [--tessdata <dir>] [--debug]
string imageArg = "image/docBack.jpg";
string language = "ocrb";
string tessData = Path.Combine(AppContext.BaseDirectory, "tessdata");
bool debug = false;

for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--lang": language = args[++i]; break;
        case "--tessdata": tessData = args[++i]; break;
        case "--debug": debug = true; break;
        default: imageArg = args[i]; break;
    }
}

string? imagePath = FindFile(imageArg);
if (imagePath is null)
{
    Console.Error.WriteLine($"Image not found: {imageArg}");
    return 1;
}

using var bitmap = SKBitmap.Decode(imagePath);
if (bitmap is null)
{
    Console.Error.WriteLine($"Could not decode image: {imagePath}");
    return 1;
}

// ocrb.traineddata is not redistributable, so it is downloaded separately (see README); fall back to eng.
if (language == "ocrb" && !File.Exists(Path.Combine(tessData, "ocrb.traineddata")))
{
    Console.Error.WriteLine("ocrb.traineddata not found, using eng (less accurate). See README to download the OCR-B model.");
    language = "eng";
}

using var ocr = new Tesseract(tessData, language);
ocr.SetPageSegMode(PageSegMode.SingleBlock);
ocr.SetVariable("tessedit_char_whitelist", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<");
ocr.SetVariable("load_system_dawg", "0");
ocr.SetVariable("load_freq_dawg", "0");

// OCR quality depends a lot on crop and scale, so try a few variants and keep the one
// that passes the most check digits. Stop early once everything validates.
MrzResult? best = null;
foreach (double bottom in new[] { 0.45, 0.6, 1.0 })
foreach (float scale in new[] { 3f, 2f, 4f })
foreach (bool binarize in new[] { false, true })
{
    var image = ImagePreprocessor.Prepare(bitmap, bottom, scale);
    if (binarize) image = ImagePreprocessor.Binarize(image);

    string text = ocr.Recognize(image.Pixels, image.Width, image.Height);
    var result = MrzParser.Parse(text);
    if (debug)
    {
        Console.Error.WriteLine($"--- bottom={bottom:P0} scale={scale} binarize={binarize} " +
                                $"checks={result?.ValidChecks ?? 0}/{result?.Checks.Count ?? 0}");
        Console.Error.WriteLine(text.TrimEnd());
    }

    if (result is not null && (best is null || result.ValidChecks > best.ValidChecks)) best = result;
    if (best?.IsValid == true) goto done;
}
done:

if (best is null)
{
    Console.Error.WriteLine("No MRZ found in image.");
    return 2;
}

Console.WriteLine($"Image  : {imagePath}");
Console.WriteLine($"Format : {best.Format}");
Console.WriteLine();
Console.WriteLine("MRZ:");
foreach (string line in best.Lines) Console.WriteLine($"  {line}");
Console.WriteLine();
Console.WriteLine("MRZ String:");
Console.WriteLine(string.Join("|", best.Lines));
Console.WriteLine();
Console.WriteLine($"Document code   : {best.DocumentCode}");
Console.WriteLine($"Issuing state   : {best.IssuingState}");
Console.WriteLine($"Document number : {best.DocumentNumber}");
Console.WriteLine($"Surname         : {best.Surname}");
Console.WriteLine($"Given names     : {best.GivenNames}");
Console.WriteLine($"Nationality     : {best.Nationality}");
Console.WriteLine($"Date of birth   : {best.DateOfBirth:yyyy-MM-dd}");
Console.WriteLine($"Sex             : {best.Sex}");
Console.WriteLine($"Date of expiry  : {best.DateOfExpiry:yyyy-MM-dd}");
Console.WriteLine($"Optional data 1 : {best.OptionalData1}");
if (best.Format == MrzFormat.TD1)
    Console.WriteLine($"Optional data 2 : {best.OptionalData2}");
Console.WriteLine();
Console.WriteLine("Check digits:");
foreach (var check in best.Checks)
    Console.WriteLine($"  {check.Field,-16}: {(check.Valid ? "OK" : "FAILED")}");

return best.IsValid ? 0 : 3;

// Resolve relative paths against the current directory, then its parents, so the default
// works whether the app is started from the repo root or from the project folder.
static string? FindFile(string path)
{
    if (Path.IsPathRooted(path)) return File.Exists(path) ? path : null;
    for (var dir = new DirectoryInfo(Directory.GetCurrentDirectory()); dir is not null; dir = dir.Parent)
    {
        string candidate = Path.Combine(dir.FullName, path);
        if (File.Exists(candidate)) return candidate;
    }
    return null;
}
