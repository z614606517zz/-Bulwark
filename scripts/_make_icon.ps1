# 生成 Bulwark 应用图标(盾牌主题)的多尺寸 .ico 文件。
# 注意:工作目录路径含中文与括号(3),全程用 .NET 方法操作路径,避免 PowerShell cmdlet 的通配符解析。
Add-Type -AssemblyName System.Drawing

# 用脚本自身位置推导路径,避免在脚本里硬编码中文路径字面量(编码问题会引入非法字符)。
$root = [System.IO.Path]::GetDirectoryName($PSScriptRoot)   # scripts 的上一级 = 项目根
$outDir = [System.IO.Path]::Combine($root, 'Bulwark.UI', 'Assets')
[System.IO.Directory]::CreateDirectory($outDir) | Out-Null
$icoPath = [System.IO.Path]::Combine($outDir, 'app.ico')

function New-ShieldBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = [float]$size
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pts = New-Object 'System.Drawing.PointF[]' 5
    $pts[0] = New-Object System.Drawing.PointF(($s*0.50), ($s*0.06))
    $pts[1] = New-Object System.Drawing.PointF(($s*0.86), ($s*0.20))
    $pts[2] = New-Object System.Drawing.PointF(($s*0.86), ($s*0.52))
    $pts[3] = New-Object System.Drawing.PointF(($s*0.50), ($s*0.94))
    $pts[4] = New-Object System.Drawing.PointF(($s*0.14), ($s*0.52))
    $path.AddPolygon($pts)

    $rect = New-Object System.Drawing.RectangleF(0, 0, $s, $s)
    $c1 = [System.Drawing.Color]::FromArgb(255, 58, 122, 224)
    $c2 = [System.Drawing.Color]::FromArgb(255, 42, 42, 90)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $c1, $c2, 90.0)
    $g.FillPath($brush, $path)

    $penW = [Math]::Max(1.0, $s*0.03)
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 230, 235, 245), $penW)
    $g.DrawPath($pen, $path)

    $cpen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [Math]::Max(1.5, $s*0.08))
    $cpen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $cpen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawLines($cpen, @(
        (New-Object System.Drawing.PointF(($s*0.34), ($s*0.50))),
        (New-Object System.Drawing.PointF(($s*0.45), ($s*0.62))),
        (New-Object System.Drawing.PointF(($s*0.68), ($s*0.36)))
    ))

    $g.Dispose(); $brush.Dispose(); $pen.Dispose(); $cpen.Dispose(); $path.Dispose()
    return $bmp
}

$sizes = @(16,32,48,64,128,256)
$pngList = New-Object System.Collections.ArrayList
foreach ($sz in $sizes) {
    $b = New-ShieldBitmap $sz
    $ms = New-Object System.IO.MemoryStream
    $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    [void]$pngList.Add($ms.ToArray())
    $b.Dispose(); $ms.Dispose()
}

# 用 MemoryStream 组装 ICO,最后一次性写盘(避免 cmdlet 路径解析)
$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
$bw.Write([uint16]0)
$bw.Write([uint16]1)
$bw.Write([uint16]$sizes.Count)
$offset = 6 + (16 * $sizes.Count)
for ($i=0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]
    $data = $pngList[$i]
    $dim = [byte]($(if ($sz -ge 256) {0} else {$sz}))
    $bw.Write($dim)
    $bw.Write($dim)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([uint16]1)
    $bw.Write([uint16]32)
    $bw.Write([uint32]$data.Length)
    $bw.Write([uint32]$offset)
    $offset += $data.Length
}
for ($i=0; $i -lt $sizes.Count; $i++) { $bw.Write([byte[]]$pngList[$i]) }
$bw.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $out.ToArray())
$bw.Dispose(); $out.Dispose()

$len = ([System.IO.FileInfo]::new($icoPath)).Length
Write-Output ("ICON_WRITTEN len=" + $len)
