using MrzReader;
using SkiaSharp;

// Usage: MrzReader [image] [--lang auto|ocrbfast|ocrb|eng] [--tessdata <dir>] [--debug]
string imageArg = "image/docBack.jpg";
string language = "auto";
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

// Prefer the integer OCR-B model (fastest), then the float one, then eng. The OCR-B models are not
// redistributable, so they are downloaded separately (see README).
if (language == "auto")
{
    language = new[] { "ocrbfast", "ocrb" }.FirstOrDefault(l => File.Exists(Path.Combine(tessData, $"{l}.traineddata"))) ?? "eng";
    if (language == "eng")
        Console.Error.WriteLine("OCR-B model not found, using eng (less accurate). See README to download it.");
}

// OCR quality depends on crop and scale, so several variants are tried, cheapest first, a few at a time
// in parallel (one Tesseract engine per worker). Stop as soon as all check digits pass, or when two
// variants agree on the same MRZ (the document's own check digits may be wrong, e.g. a specimen).
var clock = System.Diagnostics.Stopwatch.StartNew();
var variants = (
    from bottom in new[] { 0.45, 0.6, 1.0 }
    from scale in new[] { 2f, 3f, 4f }
    from binarize in new[] { true, false }
    select (Bottom: bottom, Scale: scale, Binarize: binarize)).ToArray();

int workers = Math.Clamp(Environment.ProcessorCount / 2, 1, 4);
var engines = new Tesseract?[workers];
MrzResult? best = null;
var seen = new Dictionary<string, int>();

try
{
    foreach (var batch in variants.Chunk(workers))
    {
        var outcomes = new (string Text, MrzResult? Result, long Ms, int Width, int Height)[batch.Length];
        Parallel.For(0, batch.Length, i =>
        {
            long started = clock.ElapsedMilliseconds;
            var engine = engines[i] ??= CreateEngine(tessData, language);
            var image = ImagePreprocessor.Prepare(bitmap, batch[i].Bottom, batch[i].Scale);
            if (batch[i].Binarize) image = ImagePreprocessor.Binarize(image);
            string text = engine.Recognize(image.Pixels, image.Width, image.Height);
            outcomes[i] = (text, MrzParser.Parse(text), clock.ElapsedMilliseconds - started, image.Width, image.Height);
        });

        bool stable = false;
        for (int i = 0; i < batch.Length; i++)
        {
            var (text, result, ms, width, height) = outcomes[i];
            if (debug)
            {
                Console.Error.WriteLine($"--- bottom={batch[i].Bottom:P0} scale={batch[i].Scale} binarize={batch[i].Binarize} " +
                                        $"checks={result?.ValidChecks ?? 0}/{result?.Checks.Count ?? 0} " +
                                        $"corrections={result?.Corrections ?? 0} {width}x{height} {ms} ms");
                Console.Error.WriteLine(text.TrimEnd());
            }
            if (result is null) continue;
            if (best is null || result.Score > best.Score) best = result;
            string key = string.Join('|', result.Lines);
            stable |= (seen[key] = seen.GetValueOrDefault(key) + 1) >= 2 && key == string.Join('|', best.Lines);
        }
        if (best?.IsValid == true || stable) break;
    }
}
finally
{
    foreach (var engine in engines) engine?.Dispose();
}
if (debug) Console.Error.WriteLine($"OCR total ({language}, {workers} workers): {clock.ElapsedMilliseconds} ms");

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

static Tesseract CreateEngine(string tessData, string language)
{
    var engine = new Tesseract(tessData, language);
    engine.SetPageSegMode(PageSegMode.SingleBlock);
    engine.SetVariable("tessedit_char_whitelist", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<");
    engine.SetVariable("load_system_dawg", "0");
    engine.SetVariable("load_freq_dawg", "0");
    engine.SetVariable("tessedit_do_invert", "0"); // MRZ is never white-on-black; skip the inverted-text pass
    return engine;
}

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
