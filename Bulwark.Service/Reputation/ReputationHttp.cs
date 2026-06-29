using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace Bulwark.Service.Reputation;

/// <summary>
/// 信誉客户端共用的 HttpClient 构造助手。
///
/// 统一使用 <see cref="SocketsHttpHandler"/>(.NET 托管 TLS 栈 / SslStream),绕开
/// Windows Schannel 在服务/SYSTEM 上下文下偶发的 "Authentication failed";并提供
/// 显式服务器证书校验回调(用系统根存储重建链校验,不盲目放行)。
///
/// 与 VirusTotalClient 内联实现保持一致的安全策略:名称不匹配/链断裂一律拒绝,
/// 仅吊销脱机/未知等非致命瑕疵在服务上下文下放行。
/// </summary>
internal static class ReputationHttp
{
    private static readonly string DiagDir = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bulwark");

    /// <summary>构造一个带托管 TLS 与系统根校验的 HttpClient。</summary>
    public static HttpClient Create(TimeSpan timeout, string diagTag)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            ConnectTimeout = TimeSpan.FromSeconds(15),
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                                    | System.Security.Authentication.SslProtocols.Tls13,
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                    ValidateServerCertificate(cert as X509Certificate2, chain, errors, diagTag),
            },
        };
        return new HttpClient(handler) { Timeout = timeout };
    }

    /// <summary>把一行诊断追加到 %ProgramData%\Bulwark\rep_diag.log。</summary>
    public static void DiagLog(string line)
    {
        try
        {
            System.IO.Directory.CreateDirectory(DiagDir);
            System.IO.File.AppendAllText(System.IO.Path.Combine(DiagDir, "rep_diag.log"),
                $"{DateTime.Now:HH:mm:ss} {line}{Environment.NewLine}");
        }
        catch { }
    }

    private static bool ValidateServerCertificate(
        X509Certificate2? cert, X509Chain? chain, SslPolicyErrors errors, string diagTag)
    {
        if (errors == SslPolicyErrors.None) return true;

        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            DiagLog($"{diagTag} cert: name mismatch -> reject");
            return false;
        }
        if (cert is null) { DiagLog($"{diagTag} cert: null -> reject"); return false; }

        try
        {
            using var ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            ch.ChainPolicy.VerificationFlags =
                X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreCtlSignerRevocationUnknown
                | X509VerificationFlags.IgnoreRootRevocationUnknown;

            if (ch.Build(cert)) return true;

            bool onlyBenign = true;
            foreach (var st in ch.ChainStatus)
            {
                var s = st.Status;
                bool benign = s == X509ChainStatusFlags.NoError
                    || s == X509ChainStatusFlags.RevocationStatusUnknown
                    || s == X509ChainStatusFlags.OfflineRevocation;
                if (!benign) { onlyBenign = false; DiagLog($"{diagTag} cert: chain status {s} -> reject"); }
            }
            return onlyBenign;
        }
        catch (Exception ex)
        {
            DiagLog($"{diagTag} cert: chain build EX {ex.Message} -> reject");
            return false;
        }
    }
}
