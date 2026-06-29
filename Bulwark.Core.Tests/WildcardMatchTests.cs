using Bulwark.Core.Models;
using Xunit;

namespace Bulwark.Core.Tests;

/// <summary>
/// <see cref="DefenseRule.WildcardMatch"/> 是所有规则匹配的基础,必须覆盖:
/// '*' 任意长度、'?' 单字符、大小写不敏感、空串/边界、连续通配符等。
/// </summary>
public class WildcardMatchTests
{
    [Theory]
    // 基本相等(大小写不敏感)
    [InlineData("abc", "abc", true)]
    [InlineData("ABC", "abc", true)]
    [InlineData("abc", "ABC", true)]
    [InlineData("abc", "abd", false)]
    // '*' 语义
    [InlineData("*", "", true)]
    [InlineData("*", "anything", true)]
    [InlineData("a*", "abc", true)]
    [InlineData("*c", "abc", true)]
    [InlineData("a*c", "abc", true)]
    [InlineData("a*c", "ac", true)]
    [InlineData("a*c", "abbbbc", true)]
    [InlineData("a*c", "abd", false)]
    // '?' 语义
    [InlineData("a?c", "abc", true)]
    [InlineData("a?c", "ac", false)]
    [InlineData("a?c", "abbc", false)]
    // 连续通配符
    [InlineData("a**c", "abc", true)]
    [InlineData("**", "xyz", true)]
    [InlineData("*?*", "a", true)]
    [InlineData("*?*", "", false)]
    // 空模式匹配任意(实现约定:空 pattern => true)
    [InlineData("", "abc", true)]
    [InlineData("", "", true)]
    public void Match_Cases(string pattern, string input, bool expected)
    {
        Assert.Equal(expected, DefenseRule.WildcardMatch(pattern, input));
    }

    [Theory]
    // 典型路径/注册表/命令行通配场景(规则里真实使用的形态)
    [InlineData(@"*\CurrentVersion\Run\*", @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil", true)]
    [InlineData(@"*\AppData\*.dll", @"C:\Users\me\AppData\Local\x\bad.dll", true)]
    [InlineData(@"*.pdf.exe", @"C:\Temp\invoice.pdf.exe", true)]
    [InlineData(@"*powershell*-enc*", @"powershell.exe -nop -enc ZQBjAGgA", true)]
    [InlineData(@"*\lsass.exe", @"C:\Windows\System32\lsass.exe", true)]
    [InlineData(@"*\AppData\*.dll", @"C:\Program Files\app\good.dll", false)]
    [InlineData(@"*vssadmin*delete*shadows*", @"vssadmin.exe delete shadows /all /quiet", true)]
    public void Match_RealWorldPatterns(string pattern, string input, bool expected)
    {
        Assert.Equal(expected, DefenseRule.WildcardMatch(pattern, input));
    }

    [Fact]
    public void Match_IsCaseInsensitive_ForPaths()
    {
        Assert.True(DefenseRule.WildcardMatch(@"*\LSASS.EXE", @"c:\windows\system32\lsass.exe"));
    }
}
