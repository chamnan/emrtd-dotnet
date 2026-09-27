using SkiaSharp;

namespace MrzReader;

/// <summary>An 8-bit grayscale image, one byte per pixel, row-major.</summary>
internal sealed record GrayImage(byte[] Pixels, int Width, int Height);

internal static class ImagePreprocessor
{
    /// <summary>
    /// Crops the bottom <paramref name="bottomFraction"/> of the image (where the MRZ lives),
    /// scales it so the MRZ glyphs are large enough for Tesseract, and converts to grayscale.
    /// </summary>
    public static GrayImage Prepare(SKBitmap source, double bottomFraction, float scale)
    {
        int cropTop = (int)(source.Height * (1 - bottomFraction));
        var srcRect = new SKRect(0, cropTop, source.Width, source.Height);
        int width = (int)(srcRect.Width * scale);
        int height = (int)(srcRect.Height * scale);

        using var target = new SKBitmap(new SKImageInfo(width, height, SKColorType.Rgba8888, SKAlphaType.Premul));
        using (var canvas = new SKCanvas(target))
        using (var image = SKImage.FromBitmap(source))
        {
            canvas.Clear(SKColors.White);
            canvas.DrawImage(image, srcRect, new SKRect(0, 0, width, height),
                new SKSamplingOptions(SKCubicResampler.Mitchell));
        }

        ReadOnlySpan<byte> rgba = target.GetPixelSpan();
        var gray = new byte[width * height];
        for (int i = 0; i < gray.Length; i++)
        {
            int o = i * 4;
            gray[i] = (byte)((rgba[o] * 299 + rgba[o + 1] * 587 + rgba[o + 2] * 114) / 1000);
        }
        return new GrayImage(gray, width, height);
    }

    /// <summary>Global Otsu threshold: produces black text on a white background.</summary>
    public static GrayImage Binarize(GrayImage img)
    {
        Span<int> histogram = stackalloc int[256];
        foreach (byte p in img.Pixels) histogram[p]++;

        long total = img.Pixels.Length, sumAll = 0;
        for (int i = 0; i < 256; i++) sumAll += (long)i * histogram[i];

        long sumBack = 0, weightBack = 0;
        double bestVariance = 0;
        int threshold = 128;
        for (int t = 0; t < 256; t++)
        {
            weightBack += histogram[t];
            if (weightBack == 0) continue;
            long weightFore = total - weightBack;
            if (weightFore == 0) break;

            sumBack += (long)t * histogram[t];
            double meanBack = (double)sumBack / weightBack;
            double meanFore = (double)(sumAll - sumBack) / weightFore;
            double variance = (double)weightBack * weightFore * (meanBack - meanFore) * (meanBack - meanFore);
            if (variance > bestVariance)
            {
                bestVariance = variance;
                threshold = t;
            }
        }

        var output = new byte[img.Pixels.Length];
        for (int i = 0; i < output.Length; i++)
            output[i] = img.Pixels[i] > threshold ? (byte)255 : (byte)0;
        return img with { Pixels = output };
    }
}
