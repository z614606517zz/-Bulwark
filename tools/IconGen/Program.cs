using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

// ============================================================
// Bulwark 品牌图标生成器
// 设计:科幻 HUD 风格的盾牌 + 钻石核心,霓虹青色描边,深空背景。
// 对应品牌符号 "◆ BULWARK",配色取自应用主题:
//   BgVoid   #04060C   NeonCyan #22E6FF   NeonTeal #15F0C8   NeonBlue #3B82F6
// 输出:多分辨率 .ico(16~256) + 256px .png
// ============================================================

string outDir = args.Length > 0 ? args[0] : ".";
Directory.CreateDirectory(outDir);

int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };
var pngBytesBySize = new Dictionary<int, byte[]>();

foreach (var size in sizes)
{
    using var bmp = Render(size);
    using var ms = new MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    pngBytesBySize[size] = ms.ToArray();
}

// 保存 256 PNG
File.WriteAllBytes(Path.Combine(outDir, "bulwark.png"), pngBytesBySize[256]);

// 打包成 ICO(PNG-compressed entries,Vista+ 支持)
WriteIco(Path.Combine(outDir, "bulwark.ico"), pngBytesBySize);

Console.WriteLine("图标已生成: bulwark.ico / bulwark.png -> " + Path.GetFullPath(outDir));


// ---------------- 绘制 ----------------
static Bitmap Render(int s)
{
    var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb);
    using var g = Graphics.FromImage(bmp);
    g.SmoothingMode = SmoothingMode.AntiAlias;
    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
    g.Clear(Color.Transparent);

    float u = s / 256f; // 缩放单位(基于 256 画布设计)

    // 颜色
    var bgTop = ColorTranslator.FromHtml("#0C1322");
    var bgBot = ColorTranslator.FromHtml("#04060C");
    var cyan = ColorTranslator.FromHtml("#22E6FF");
    var teal = ColorTranslator.FromHtml("#15F0C8");
    var blue = ColorTranslator.FromHtml("#3B82F6");

    // 盾牌轮廓路径(heater shield):顶部平、两侧直、底部收尖
    using var shield = ShieldPath(s, u);

    // 1) 盾内填充(竖直渐变)
    using (var fill = new LinearGradientBrush(
        new PointF(0, 0), new PointF(0, s), bgTop, bgBot))
    {
        g.FillPath(fill, shield);
    }

    // 2) 外发光(多层半透明描边,模拟霓虹辉光)
    for (int i = 3; i >= 1; i--)
    {
        int alpha = 28 * i;
        using var glow = new Pen(Color.FromArgb(alpha, cyan), (10f - i * 2f) * u)
        {
            LineJoin = LineJoin.Round
        };
        g.DrawPath(glow, shield);
    }

    // 3) 主描边(青->蓝渐变)
    using (var strokeBrush = new LinearGradientBrush(
        new PointF(0, 0), new PointF(s, s), cyan, blue))
    using (var stroke = new Pen(strokeBrush, 6f * u) { LineJoin = LineJoin.Round })
    {
        g.DrawPath(stroke, shield);
    }

    // 4) 内部 HUD 横线(两条细线,科幻仪表感)
    using (var line = new Pen(Color.FromArgb(90, teal), 1.6f * u))
    {
        g.DrawLine(line, 70 * u, 96 * u, 186 * u, 96 * u);
        g.DrawLine(line, 60 * u, 150 * u, 196 * u, 150 * u);
    }

    // 5) 中心钻石 ◆(品牌符号),带辉光
    using (var diamond = DiamondPath(s, u))
    {
        // 钻石辉光
        for (int i = 3; i >= 1; i--)
        {
            using var dg = new Pen(Color.FromArgb(26 * i, cyan), (7f - i * 1.5f) * u)
            { LineJoin = LineJoin.Round };
            g.DrawPath(dg, diamond);
        }
        // 钻石填充(青->teal 渐变)
        using var dfill = new LinearGradientBrush(
            new PointF(0, 100 * u), new PointF(0, 175 * u), cyan, teal);
        g.FillPath(dfill, diamond);

        // 钻石高光描边
        using var dstroke = new Pen(Color.FromArgb(220, Color.White), 1.2f * u)
        { LineJoin = LineJoin.Round };
        g.DrawPath(dstroke, diamond);
    }

    return bmp;
}

// 盾牌路径
static GraphicsPath ShieldPath(int s, float u)
{
    var p = new GraphicsPath();
    // 设计坐标(基于 256),留出发光边距
    float left = 44 * u, right = 212 * u;
    float top = 30 * u;
    float midY = 150 * u;
    float tipY = 226 * u;
    float cx = 128 * u;

    p.AddLine(left, top, right, top);                    // 顶边
    p.AddLine(right, top, right, midY);                  // 右直边
    // 右下斜向收尖(二次曲线模拟盾底弧)
    p.AddBezier(right, midY, right, midY + 40 * u, cx + 40 * u, tipY - 18 * u, cx, tipY);
    p.AddBezier(cx, tipY, cx - 40 * u, tipY - 18 * u, left, midY + 40 * u, left, midY);
    p.AddLine(left, midY, left, top);                    // 左直边
    p.CloseFigure();
    return p;
}

// 中心钻石路径
static GraphicsPath DiamondPath(int s, float u)
{
    var p = new GraphicsPath();
    float cx = 128 * u, cy = 132 * u;
    float w = 34 * u, h = 44 * u;
    p.AddPolygon(new[]
    {
        new PointF(cx, cy - h),
        new PointF(cx + w, cy),
        new PointF(cx, cy + h),
        new PointF(cx - w, cy),
    });
    return p;
}

// ---------------- ICO 封装 ----------------
// ICO 文件结构:ICONDIR(6 字节) + ICONDIRENTRY(16 字节 * n) + 各图像数据(PNG)
static void WriteIco(string path, Dictionary<int, byte[]> images)
{
    using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
    using var bw = new BinaryWriter(fs);

    var entries = images.OrderBy(kv => kv.Key).ToList();
    int count = entries.Count;

    // ICONDIR
    bw.Write((short)0);      // reserved
    bw.Write((short)1);      // type: 1 = icon
    bw.Write((short)count);  // image count

    int offset = 6 + 16 * count;
    foreach (var (size, data) in entries)
    {
        // ICONDIRENTRY
        bw.Write((byte)(size >= 256 ? 0 : size)); // width (0 = 256)
        bw.Write((byte)(size >= 256 ? 0 : size)); // height
        bw.Write((byte)0);   // color count
        bw.Write((byte)0);   // reserved
        bw.Write((short)1);  // color planes
        bw.Write((short)32); // bits per pixel
        bw.Write(data.Length);
        bw.Write(offset);
        offset += data.Length;
    }
    foreach (var (_, data) in entries)
        bw.Write(data);
}
