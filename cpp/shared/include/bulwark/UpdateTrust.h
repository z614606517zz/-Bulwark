#pragma once

#include <QSet>
#include <QString>
#include <QStringList>

// =====================================================================
//  在线更新的【信任锚点】。
//
//  为什么这个文件必须存在,而且必须是这套判据
//  ------------------------------------------------------------------
//  在线更新的本质是「从网上取一段代码,放进安装目录,然后以 SYSTEM 跑起来」。
//  对一个 HIPS 来说,这是产品里最危险的一条通路 —— 它一旦被人利用,拿到的不是
//  某个用户的文件,而是每一台装了本产品的机器的内核。
//
//  所以「服务器给的哈希对得上」【不是】安全判据:哈希是服务器自己声明的,服务器
//  被拿下、或者 TLS 被中间人拆开,攻击者就能同时给出恶意文件和与之匹配的哈希。
//  哈希只能证明「下载没坏」,证明不了「这是我们发的」。
//
//  真正的判据只有一条:每一个要装进去的 PE 都必须带 Authenticode 签名,且签名者
//  证书指纹在下面这份钉死的名单里。攻击者可以伪造清单、伪造哈希、伪造整个服务器,
//  但拿不到我们的签名私钥,就产不出能通过这一关的文件。
//
//  配套的三条硬规则(实现在 UpdateService / bulwark.ps1 -ApplyUpdate 两侧,
//  故意两边都做一遍 —— 下载侧被绕过时,提权应用侧仍是最后一道闸):
//    1) 只允许下面 kUpdatePayloadAllowList 里的文件名,且名字里不得含路径分隔符。
//       否则一份恶意清单可以写 "..\\..\\Windows\\System32\\xxx.dll" 把文件投到别处。
//    2) 只允许 PE(.exe/.dll/.sys)。脚本和配置【不走在线更新】—— 它们现在没有签名,
//       无法验证来源,而 bulwark.ps1 恰恰是提权执行的那一个。要改脚本请重新下载整包。
//    3) 端点必须是 https。
//
//  ⚠ 指纹与实际签名之间的不变量
//     下面这个值必须等于「实际签了随包 Bulwark.sys 的那张证书」的指纹。
//     verify_portable.ps1 会读取本文件、读取包里 Bulwark.sys 的签名者指纹,
//     并核对两者一致 —— 换证书时漏改这里,会被打包前的验证直接拦下,而不是等到
//     用户点了更新才发现「签名校验永远失败」。
// =====================================================================

// CN=BulwarkTestCert(代码签名 EKU,有效期至 2027-08-04)。
// 换证书时:改这里 + packaging\portable-scripts\bulwark.ps1 的 $UpdateSignerThumbprints,
// 然后跑 verify_portable.ps1 核对。
#define BULWARK_UPDATE_SIGNER_THUMBPRINT "712BA1C841C8D2AA0A48BF89BD076DCD0774E7F5"

namespace bulwark::update {

// 指纹规范化:去掉空格/冒号并大写。Get-AuthenticodeSignature、certutil、
// 证书管理器复制出来的指纹格式各不相同(带空格、带冒号、大小写混杂),
// 直接字符串比较必然出现「明明是同一张证书却判不通过」。
inline QString normalizeThumbprint(const QString& raw)
{
    QString out;
    out.reserve(raw.size());
    for (const QChar c : raw) {
        if (c.isLetterOrNumber())
            out.append(c.toUpper());
    }
    return out;
}

// 钉死的签名者指纹集合。配置里的 Update.AllowedThumbprints 只能【追加】,
// 不能替换掉内置项 —— 否则改一行配置就能把整条信任链换掉,而配置文件是
// 攻击者拿到本机写权限后最容易改的东西。
inline QSet<QString> pinnedThumbprints(const QStringList& extraFromConfig = {})
{
    QSet<QString> s;
    s.insert(normalizeThumbprint(QString::fromLatin1(BULWARK_UPDATE_SIGNER_THUMBPRINT)));
    for (const QString& t : extraFromConfig) {
        const QString n = normalizeThumbprint(t);
        if (n.size() >= 32) // 明显不是指纹的短串直接忽略,避免配错就放空门
            s.insert(n);
    }
    return s;
}

// 允许经在线更新替换的文件。故意是白名单而不是黑名单:清单由服务器提供,
// 黑名单意味着「没想到的都放行」。
//
// 刻意【不含】appsettings.json、*.bat、*.ps1、使用说明.txt:
//   · 配置文件里有用户自己填的密钥和信任目录,覆盖掉等于把用户设置清了;
//   · 脚本没有签名,无法验证来源,而它们是提权执行的那一批。
// 这两类要变更,走「重新下载整包」这条路 —— 那是一次用户明确知情的操作。
inline const QStringList& payloadAllowList()
{
    static const QStringList s = {
        QStringLiteral("bulwark_service.exe"),
        QStringLiteral("bulwark_ui.exe"),
        QStringLiteral("Bulwark.sys"),
    };
    return s;
}

// 文件名是否可接受:必须在白名单里(大小写不敏感),且不含任何路径成分。
inline bool isAllowedPayloadName(const QString& name)
{
    if (name.isEmpty() || name.size() > 64)
        return false;
    // 路径穿越防线。清单是服务器给的,所以这里假定它可能是恶意的。
    if (name.contains(QLatin1Char('/')) || name.contains(QLatin1Char('\\'))
        || name.contains(QLatin1Char(':')) || name.contains(QStringLiteral("..")))
        return false;
    for (const QString& allowed : payloadAllowList()) {
        if (name.compare(allowed, Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

// 是否为需要做签名校验的 PE。白名单里目前全是 PE,这个判断留作显式表达:
// 将来若放开某类非 PE 文件,漏掉签名校验会是静默的,而这里会显式挡住。
inline bool requiresSignature(const QString& name)
{
    return name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)
           || name.endsWith(QStringLiteral(".dll"), Qt::CaseInsensitive)
           || name.endsWith(QStringLiteral(".sys"), Qt::CaseInsensitive);
}

} // namespace bulwark::update
