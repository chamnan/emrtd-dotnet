using System.Reflection;
using System.Runtime.InteropServices;

namespace MrzReader;

/// <summary>
/// Minimal wrapper over the Tesseract 5 C API (capi.h). Images are passed as raw
/// 8-bit grayscale buffers, so no Leptonica interop is needed.
/// </summary>
internal sealed partial class Tesseract : IDisposable
{
    private const string Lib = "tesseract";
    private nint _handle;

    static Tesseract() => NativeLibrary.SetDllImportResolver(typeof(Tesseract).Assembly, Resolve);

    public Tesseract(string dataPath, string language)
    {
        _handle = TessBaseAPICreate();
        if (TessBaseAPIInit3(_handle, dataPath, language) != 0)
        {
            TessBaseAPIDelete(_handle);
            _handle = 0;
            throw new InvalidOperationException(
                $"Tesseract could not load language '{language}' from '{dataPath}'.");
        }
    }

    public void SetVariable(string name, string value)
    {
        if (TessBaseAPISetVariable(_handle, name, value) == 0)
            throw new ArgumentException($"Unknown Tesseract variable '{name}'.");
    }

    public void SetPageSegMode(PageSegMode mode) => TessBaseAPISetPageSegMode(_handle, (int)mode);

    public unsafe string Recognize(byte[] gray, int width, int height, int dpi = 300)
    {
        fixed (byte* p = gray)
        {
            TessBaseAPISetImage(_handle, p, width, height, 1, width);
            TessBaseAPISetSourceResolution(_handle, dpi);
            nint text = TessBaseAPIGetUTF8Text(_handle);
            try
            {
                return Marshal.PtrToStringUTF8(text) ?? "";
            }
            finally
            {
                TessDeleteText(text);
                TessBaseAPIClear(_handle);
            }
        }
    }

    public void Dispose()
    {
        if (_handle == 0) return;
        TessBaseAPIEnd(_handle);
        TessBaseAPIDelete(_handle);
        _handle = 0;
    }

    // Tesseract ships under different file names per platform/installer; probe the usual ones.
    private static nint Resolve(string name, Assembly assembly, DllImportSearchPath? path)
    {
        if (name != Lib) return 0;

        var candidates = new List<string>();
        if (Environment.GetEnvironmentVariable("TESSERACT_LIB") is { Length: > 0 } custom)
            candidates.Add(custom);

        if (OperatingSystem.IsWindows())
        {
            candidates.AddRange(["libtesseract-5.dll", "tesseract55.dll", "tesseract54.dll",
                                 "tesseract53.dll", "tesseract50.dll", "tesseract.dll"]);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            candidates.Add(Path.Combine(programFiles, "Tesseract-OCR", "libtesseract-5.dll"));
        }
        else if (OperatingSystem.IsMacOS())
        {
            candidates.AddRange(["libtesseract.5.dylib", "/opt/homebrew/lib/libtesseract.5.dylib",
                                 "/usr/local/lib/libtesseract.5.dylib", "/opt/local/lib/libtesseract.5.dylib"]);
        }
        else
        {
            candidates.AddRange(["libtesseract.so.5", "libtesseract.so"]);
        }

        foreach (string candidate in candidates)
        {
            if (NativeLibrary.TryLoad(candidate, assembly, path, out nint handle))
                return handle;
        }

        throw new DllNotFoundException(
            "Tesseract 5 native library not found. Install Tesseract (Windows: UB Mannheim installer, " +
            "macOS: 'brew install tesseract', Linux: 'apt install libtesseract5') or set TESSERACT_LIB " +
            "to the full path of the library. Tried: " + string.Join(", ", candidates));
    }

    [LibraryImport(Lib)] private static partial nint TessBaseAPICreate();
    [LibraryImport(Lib)] private static partial void TessBaseAPIDelete(nint handle);
    [LibraryImport(Lib)] private static partial void TessBaseAPIEnd(nint handle);
    [LibraryImport(Lib)] private static partial void TessBaseAPIClear(nint handle);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int TessBaseAPIInit3(nint handle, string datapath, string language);

    [LibraryImport(Lib, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int TessBaseAPISetVariable(nint handle, string name, string value);

    [LibraryImport(Lib)] private static partial void TessBaseAPISetPageSegMode(nint handle, int mode);

    [LibraryImport(Lib)]
    private static unsafe partial void TessBaseAPISetImage(
        nint handle, byte* imagedata, int width, int height, int bytesPerPixel, int bytesPerLine);

    [LibraryImport(Lib)] private static partial void TessBaseAPISetSourceResolution(nint handle, int ppi);
    [LibraryImport(Lib)] private static partial nint TessBaseAPIGetUTF8Text(nint handle);
    [LibraryImport(Lib)] private static partial void TessDeleteText(nint text);
}

internal enum PageSegMode
{
    Auto = 3,
    SingleColumn = 4,
    SingleBlock = 6,
    SparseText = 11,
}
