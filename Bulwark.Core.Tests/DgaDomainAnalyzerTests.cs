using Bulwark.Core.Engine;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="DgaDomainAnalyzer"/>:从域名字符串统计特征识别 DGA 随机域名,
/// 不依赖黑名单。核心是降误报(正常品牌域名/CDN/IP 0 分)+ 抓随机域名(高分)。
/// </summary>
public class DgaDomainAnalyzerTests
{
    [Theory]
    [InlineData("google.com:443")]
    [InlineData("www.microsoft.com")]
    [InlineData("update.googleapis.com:443")]
    [InlineData("github.com")]
    [InlineData("stackoverflow.com")]
    [InlineData("login.live.com")]
    public void NormalDomains_ScoreLow(string host)
    {
        var (score, _) = DgaDomainAnalyzer.Analyze(host);
        Assert.True(score < 30, $"正常域名应低分,实际 {score}({host})");
    }

    [Theory]
    [InlineData("8.8.8.8:53")]
    [InlineData("203.0.113.66:443")]
    [InlineData("2001:db8::1")]
    public void IpAddresses_ReturnZero(string target)
    {
        var (score, reasons) = DgaDomainAnalyzer.Analyze(target);
        Assert.Equal(0, score);
        Assert.Empty(reasons);
    }

    [Theory]
    [InlineData("kq3v9zxlwprmfg.com:443")]
    [InlineData("xnzqwbvkptlrdh.net")]
    [InlineData("vhgktrqplmnzxcv.info:8080")]
    public void DgaLikeDomains_ScoreHigh(string host)
    {
        var (score, reasons) = DgaDomainAnalyzer.Analyze(host);
        Assert.True(score >= 30, $"DGA 域名应高分,实际 {score}({host})");
        Assert.NotEmpty(reasons);
    }

    [Fact]
    public void BenignCdnRandomSubdomain_ReturnsZero()
    {
        // 哈希化的 CDN 子域,主体后缀可信,不评估随机度。
        var (score, _) = DgaDomainAnalyzer.Analyze("d1a2b3c4e5f6g7.cloudfront.net");
        Assert.Equal(0, score);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("a.io")]
    public void NullOrShort_ReturnsZero(string? target)
    {
        var (score, reasons) = DgaDomainAnalyzer.Analyze(target);
        Assert.Equal(0, score);
        Assert.Empty(reasons);
    }
}
