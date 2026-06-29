using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;

namespace IconGen;

/// <summary>
/// 一次性图标生成器:绘制「磐垒 BULWARK」品牌图标(深色盾牌 + 城垛 + 霓虹青菱形),
/// 输出多尺寸 bulwark.ico 与 bulwark.png。
/// </summary>
internal static class Program
{
    private static void Main(string[] args)
    {
        var outDir = args.Length > 0 ? args[0] : ".";
        Directory.CreateDirectory(outDir);

        int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };
        var pngs = sizes.Select(sz =>
        {
            using var b = Draw(sz);
            using var ms = new MemoryStream();
            b.Save(ms, ImageFormat.Png);
            return ms.ToArray();
        }).ToArray();

        // ===== 写多尺寸 ICO(每帧用 PNG 压缩,Vista+ 支持)=====
        var icoPath = Path.Combine(outDir, "bulwark.ico");
        using (var fs = File.Create(icoPath))
        using (var bw = new BinaryWriter(fs))
        {
            bw.Write((short)0);              // reserved
            bw.Write((short)1);              // type = icon
            bw.Write((short)sizes.Length);   // image count

            int offset = 6 + 16 * sizes.Length;
            for (int i = 0; i < sizes.Length; i++)
            {
                int sz = sizes[i];
                bw.Write((byte)(sz >= 256 ? 0 : sz));   // width
                bw.Write((byte)(sz >= 256 ? 0 : sz));   // height
                bw.Write((byte)0);                       // palette
                bw.Write((byte)0);                       // reserved
                bw.Write((short)1);                      // color planes
                bw.Write((short)32);                     // bits per pixel
                bw.Write(pngs[i].Length);                // bytes of image
                bw.Write(offset);                        // offset
                offset += pngs[i].Length;
            }
            foreach (var p in pngs) bw.Write(p);
        }

        // ===== 写 256 PNG(供 Avalonia 窗口图标)=====
        var pngPath = Path.Combine(outDir, "bulwark.png");
        File.WriteAllBytes(pngPath, pngs[^1]);

        Console.WriteLine($"OK -> {icoPath} ({new FileInfo(icoPath).Length} bytes), {pngPath}");
    }

    /// <summary>在 256 基准坐标系下绘制图标,按目标尺寸缩放。</summary>
    private static Bitmap Draw(int size)
    {
        var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        bmp.SetResolution(96, 96);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.Clear(Color.Transparent);

        float s = size / 256f;
        g.ScaleTransform(s, s);

        // 盾牌轮廓(顶部城垛 = 垒/堡垒意象,向下收成尖角 = 盾)
        PointF[] shield =
        {
            new(40, 50), new(75, 50), new(75, 72), new(110, 72), new(110, 50),
            new(146, 50), new(146, 72), new(181, 72), new(181, 50), new(216, 50),
            new(216, 152), new(128, 230), new(40, 152)
        };
        using var path = new GraphicsPath();
        path.AddPolygon(shield);

        // 外发光(青色半透明宽描边)
        using (var glow = new Pen(Color.FromArgb(70, 34, 230, 255), 26f) { LineJoin = LineJoin.Round })
            g.DrawPath(glow, path);

        // 盾体深色渐变填充
        using (var fill = new LinearGradientBrush(
                   new PointF(0, 50), new PointF(0, 230),
                   ColorTranslator.FromHtml("#12243C"),
                   ColorTranslator.FromHtml("#070D17")))
            g.FillPath(fill, path);

        // 盾边霓虹青描边
        using (var pen = new Pen(ColorTranslator.FromHtml("#22E6FF"), 12f) { LineJoin = LineJoin.Round })
            g.DrawPath(pen, path);

        // 中央菱形 ◆(呼应标题栏品牌符号)
        PointF[] diamond =
        {
            new(128, 98), new(166, 142), new(128, 186), new(90, 142)
        };
        using var dpath = new GraphicsPath();
        dpath.AddPolygon(diamond);
        using (var dGlow = new Pen(Color.FromArgb(90, 92, 240, 255), 14f) { LineJoin = LineJoin.Round })
            g.DrawPath(dGlow, dpath);
        using (var dbrush = new LinearGradientBrush(
                   new PointF(90, 98), new PointF(166, 186),
                   ColorTranslator.FromHtml("#7AF4FF"),
                   ColorTranslator.FromHtml("#16B6D6")))
            g.FillPath(dbrush, dpath);

        // 菱形内高光竖条,增加立体/科技感
        using (var hi = new SolidBrush(Color.FromArgb(150, 255, 255, 255)))
        {
            PointF[] spark = { new(128, 110), new(140, 142), new(128, 174), new(116, 142) };
            using var sp = new GraphicsPath();
            sp.AddPolygon(spark);
            // 仅左半高光
            using var halfClip = new GraphicsPath();
            halfClip.AddPolygon(new[] { new PointF(116, 142), new PointF(128, 110), new PointF(128, 174) });
            g.FillPath(new SolidBrush(Color.FromArgb(70, 255, 255, 255)), halfClip);
        }

        return bmp;
    }
}
