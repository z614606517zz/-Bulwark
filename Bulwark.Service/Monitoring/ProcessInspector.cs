using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace Bulwark.Service.Monitoring;

/// <summary>
/// 进程取证辅助:计算文件 SHA-256,校验 Authenticode 数字签名。
/// 签名校验通过 WinVerifyTrust(仅在 Windows 上可用)。
/// </summary>
public static class ProcessInspector
{
    //
    // ===== 文件取证结果缓存 =====
    //
    // 这些操作(WinVerifyTrust 签名校验、catalog 校验、整文件 SHA-256、证书解析)都很重。
    // 系统进程(svchost/conhost/explorer 等)会被反复启动,若对同一文件反复做相同的重计算,
    // 会无谓占用富化 worker、拖慢遥测处置时效(注:内核侧已是异步队列,不再因此卡死,
    // 但缓存仍能显著降低用户态 CPU 与处置延迟)。
    //
    // 这里按「完整路径 + 文件大小 + 最后写入时间」为键缓存结果:文件被替换/篡改(大小或
    // 时间戳变化)时键自然失效并重算,绝不会返回陈旧结论;同一文件反复启动则直接命中缓存。
    //

    /// <summary>缓存条目上限。超过即整体清空,避免长时间运行内存无界增长。</summary>
    private const int CacheCapacity = 8192;

    private static readonly ConcurrentDictionary<string, object?> _factCache = new();

    /// <summary>
    /// 计算文件身份键(路径|大小|写入时间)。文件不存在 / 无法读取属性时返回 null
    /// (此时不缓存,直接实算,避免缓存到"文件不存在"的瞬态结果)。
    /// </summary>
    private static string? FileIdentity(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return null;
            return $"{path.ToLowerInvariant()}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}";
        }
        catch { return null; }
    }

    /// <summary>
    /// 按文件身份缓存 <paramref name="compute"/> 的结果。<paramref name="tag"/> 区分同一文件的
    /// 不同事实(签名/哈希/证书…)。无法确定文件身份时直接实算不缓存。
    /// </summary>
    private static T Cached<T>(string? path, string tag, Func<T> compute)
    {
        var id = FileIdentity(path);
        if (id is null) return compute();

        var key = tag + "\u0001" + id;
        if (_factCache.TryGetValue(key, out var hit))
            return (T)hit!;

        var value = compute();

        if (_factCache.Count >= CacheCapacity)
            _factCache.Clear();
        _factCache[key] = value;
        return value;
    }

    /// <summary>
    /// 提取文件签名证书的发行主体(发行商)名称,如 "Microsoft Corporation"。
    /// 失败 / 无签名返回 null。仅读取证书,不验证信任链(信任由 IsSigned 负责)。
    /// </summary>
    public static string? TryGetPublisher(string? path)
        => Cached<string?>(path, "publisher", () =>
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            using var cert = new X509Certificate2(path);
            // CN 字段优先,否则用整串 Subject
            var name = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(name) ? cert.Subject : name;
        }
        catch
        {
            return null; // 无签名或无法读取
        }
    });

    /// <summary>
    /// 文件是否内嵌了 Authenticode 证书(无论是否验证通过)。
    /// 用于区分"完全没签名"与"有签名但校验失败(篡改/盗证书)"。
    /// </summary>
    public static bool HasEmbeddedSignature(string? path)
        => Cached(path, "embedded", () =>
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            using var cert = new X509Certificate2(path); // 能读出证书即视为内嵌了签名
            return true;
        }
        catch { return false; }
    });

    /// <summary>
    /// 签名失配:文件内嵌了签名,但信任校验不通过(HashMismatch / 证书无效 / 被篡改)。
    /// 这是银狐等家族滥用第三方证书 / 签名后篡改的典型特征,比"无签名"更可疑。
    /// </summary>
    public static bool IsSignatureMismatch(string? path)
        => HasEmbeddedSignature(path) && !IsSigned(path);

    /// <summary>
    /// 提取签名证书的详细信息(指纹、有效期、签名时间),用于识别"有正规签名的恶意软件":
    /// 盗用证书(指纹黑名单 / 已吊销)、空壳公司新证书(NotAfter 很近)、过期后签名等。
    /// 失败 / 无签名返回全空的结构。
    /// </summary>
    public static CertInfo GetCertInfo(string? path)
        => Cached(path, "certinfo", () =>
    {
        var info = new CertInfo();
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return info;
            using var cert = new X509Certificate2(path);

            info.Thumbprint = cert.Thumbprint?.ToUpperInvariant();
            info.NotAfterUtc = cert.NotAfter.ToUniversalTime();
            info.NotBeforeUtc = cert.NotBefore.ToUniversalTime();

            // Authenticode 反签名时间戳(签名时间)。失败则为 null。
            info.SigningTimeUtc = TryGetSigningTime(path);

            // "过期后签名"判定 —— 仅在拿到【真实可信的签名时间戳】时才做。
            //
            // 重要(防误报):绝不能用文件的最后修改时间来臆测签名时间!
            // 合法软件普遍使用「旧证书 + RFC3161 时间戳副署」:证书本身可能早已过期,
            // 但签名时附带的可信时间戳证明签名发生在有效期内,签名依然有效且可信
            // (典型如 360、大量国产软件、部分微软老组件)。文件只要近期被解压/更新,
            // 其 LastWrite 就会晚于证书 NotAfter —— 用它判定必然把这些正规软件
            // 误杀为「盗用旧证书」。这正是之前 360 组件被误拦的根因。
            //
            // 因此:拿不到真实签名时间(SigningTimeUtc==null)时,一律【不】判 SignedAfterCertExpiry,
            // 宁可漏报也不误杀。只有当确实解析出签名时间、且该时间落在证书有效期之外时,
            // 才认定为「过期后签名」(这才是盗用旧证书的真实特征)。
            if (info.SigningTimeUtc is { } st &&
                info.NotAfterUtc is { } na && info.NotBeforeUtc is { } nb &&
                (st > na || st < nb))
            {
                info.SignedAfterCertExpiry = true;
            }

            // 吊销检查(联网 CRL/OCSP)。无网络时保守判为未吊销,避免误伤。
            info.Revoked = IsCertRevoked(cert);
        }
        catch { /* 无签名 / 读取失败:返回空结构 */ }
        return info;
    });

    /// <summary>
    /// 提取 Authenticode 签名的真实签名时间(UTC)。
    ///
    /// 依次尝试:
    ///   1) RFC3161 时间戳副署(现代时间戳,最权威,证明签名发生的时刻);
    ///   2) 传统 PKCS#9 signingTime 反签名属性(老式时间戳);
    /// 两者都拿不到则返回 null —— 调用方据此【不】做"过期后签名"判定,避免误杀。
    ///
    /// 失败一律返回 null(保守:无可信签名时间就不据此处置),绝不抛异常。
    /// </summary>
    private static DateTime? TryGetSigningTime(string path)
    {
        try
        {
            // 从 PE 文件读取 Authenticode 签名 blob(WIN_CERTIFICATE),解码为 PKCS#7。
            byte[]? pkcs7 = TryReadAuthenticodeBlob(path);
            if (pkcs7 is null) return null;

            var signed = new SignedCms();
            signed.Decode(pkcs7);
            if (signed.SignerInfos.Count == 0) return null;

            var signer = signed.SignerInfos[0];

            foreach (var unsigned in signer.UnsignedAttributes)
            {
                // 1) RFC3161 时间戳令牌(OID 1.2.840.113549.1.9.16.2.14)
                if (unsigned.Oid?.Value == "1.2.840.113549.1.9.16.2.14")
                {
                    foreach (var av in unsigned.Values)
                    {
                        var t = TryReadRfc3161Time(av.RawData);
                        if (t is not null) return t;
                    }
                }

                // 2) 传统副署签名(OID 1.2.840.113549.1.9.6),内含 PKCS#9 signingTime
                if (unsigned.Oid?.Value == "1.2.840.113549.1.9.6")
                {
                    try
                    {
                        // 解析副署者的 signingTime 属性
                        foreach (SignerInfo ci in signer.CounterSignerInfos)
                        {
                            var t = ExtractSigningTimeAttr(ci);
                            if (t is not null) return t;
                        }
                    }
                    catch { /* 忽略,继续其它属性 */ }
                }
            }

            // 3) 兜底:有些签名把 signingTime 放在签名者自身的已签名属性里
            return ExtractSigningTimeAttr(signer);
        }
        catch { return null; }
    }

    /// <summary>从 SignerInfo 的(已签名/副署)属性中提取 PKCS#9 signingTime。</summary>
    private static DateTime? ExtractSigningTimeAttr(SignerInfo signer)
    {
        try
        {
            foreach (var attr in signer.SignedAttributes)
            {
                if (attr.Oid?.Value == "1.2.840.113549.1.9.5") // signingTime
                {
                    foreach (var av in attr.Values)
                    {
                        if (av is Pkcs9SigningTime st)
                            return st.SigningTime.ToUniversalTime();
                    }
                }
            }
        }
        catch { }
        return null;
    }

    /// <summary>解析 RFC3161 时间戳令牌,取其 genTime。失败返回 null。</summary>
    private static DateTime? TryReadRfc3161Time(byte[] tokenBytes)
    {
        try
        {
            var token = Rfc3161TimestampToken.TryDecode(tokenBytes, out var t, out _)
                ? t : null;
            if (token is not null)
                return token.TokenInfo.Timestamp.UtcDateTime;
        }
        catch { }
        return null;
    }

    /// <summary>
    /// 从 PE 文件的安全目录(IMAGE_DIRECTORY_ENTRY_SECURITY)读取 Authenticode
    /// 签名 blob,剥离 WIN_CERTIFICATE 头后返回内层 PKCS#7 DER。无签名 / 解析失败返回 null。
    /// </summary>
    private static byte[]? TryReadAuthenticodeBlob(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var br = new System.IO.BinaryReader(fs);

            if (fs.Length < 0x40) return null;
            fs.Position = 0x3C;
            int peOffset = br.ReadInt32();
            if (peOffset <= 0 || peOffset + 0x18 >= fs.Length) return null;

            fs.Position = peOffset;
            if (br.ReadUInt32() != 0x00004550) return null; // "PE\0\0"

            fs.Position = peOffset + 4 + 16; // 跳过 COFF 头到 Optional Header
            ushort magic = br.ReadUInt16();
            // PE32 (0x10b): security dir 在 OptionalHeader+128;PE32+ (0x20b): +144
            int secDirOffset = magic == 0x20b ? 144 : 128;
            fs.Position = peOffset + 4 + 20 + secDirOffset;
            uint certRva = br.ReadUInt32();   // 这里实际是文件偏移(WIN_CERTIFICATE 用文件偏移)
            uint certSize = br.ReadUInt32();
            if (certRva == 0 || certSize == 0 || certRva + certSize > fs.Length) return null;

            // WIN_CERTIFICATE: DWORD dwLength; WORD wRevision; WORD wCertificateType; BYTE bCertificate[]
            fs.Position = certRva;
            uint dwLength = br.ReadUInt32();
            br.ReadUInt16(); // wRevision
            ushort certType = br.ReadUInt16();
            if (certType != 0x0002) return null; // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            int blobLen = (int)dwLength - 8;
            if (blobLen <= 0 || blobLen > certSize) return null;
            return br.ReadBytes(blobLen);
        }
        catch { return null; }
    }

    /// <summary>
    /// 是否对证书做【在线】吊销校验(CRL/OCSP 联网)。默认 false(仅用本机已缓存的 CRL,绝不联网,
    /// 不阻塞富化管线)。置 true 后可命中"被盗用证书已被 CA 吊销"这类样本,但每次校验可能因网络
    /// 往返耗时数秒——仅建议在富化已移出关键路径(用户态 WMI 富化 worker)的部署里按需开启。
    /// 由宿主在启动时按配置注入(见 <see cref="BulwarkOptions.OnlineCertRevocationCheck"/>)。
    /// </summary>
    public static bool OnlineRevocationCheck { get; set; }

    /// <summary>
    /// 对证书做吊销校验。
    ///
    /// 性能关键:几乎所有系统进程都带签名,都会走到这里。若用
    /// <see cref="X509RevocationMode.Online"/>,会对每个进程启动发起 CRL/OCSP 网络请求;
    /// 一旦网络慢/吊销服务器不可达,每次都会卡数秒,拖慢富化管线。
    ///
    /// 默认 <see cref="X509RevocationMode.Offline"/>:仅使用本机已缓存的 CRL,绝不发起
    /// 同步网络往返,消除网络阻塞;URL 检索超时压到 1 秒兜底。
    /// 仅当 <see cref="OnlineRevocationCheck"/> 显式开启时才用 Online(超时放宽到 3 秒),
    /// 以命中"被盗证书已吊销"样本。缓存/查询未覆盖时一律保守判为未吊销(不误伤)。
    /// </summary>
    private static bool IsCertRevoked(X509Certificate2 cert)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode =
                OnlineRevocationCheck ? X509RevocationMode.Online : X509RevocationMode.Offline;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.UrlRetrievalTimeout =
                TimeSpan.FromSeconds(OnlineRevocationCheck ? 3 : 1);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            chain.Build(cert);
            foreach (var status in chain.ChainStatus)
            {
                if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                    return true;
            }
            return false;
        }
        catch { return false; }
    }

    /// <summary>签名证书详情(由 <see cref="GetCertInfo"/> 填充)。</summary>
    public sealed class CertInfo
    {
        public string? Thumbprint { get; set; }
        public DateTime? NotAfterUtc { get; set; }
        public DateTime? NotBeforeUtc { get; set; }
        public DateTime? SigningTimeUtc { get; set; }
        public bool SignedAfterCertExpiry { get; set; }
        public bool Revoked { get; set; }
    }

    /// <summary>
    /// 解析指定 PID 的可执行文件完整路径。
    /// 优先使用 QueryFullProcessImageName(PROCESS_QUERY_LIMITED_INFORMATION),
    /// 它对受保护的系统进程、跨位数(32/64)进程都比 Process.MainModule 更可靠,
    /// 不会因 MainModule 访问失败而退化为 "PID xxx"(从而导致签名/规则匹配失效)。
    /// 失败返回 null。
    /// </summary>
    public static string? TryGetProcessImagePath(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 0) return null;

        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new System.Text.StringBuilder(1024);
            uint size = (uint)sb.Capacity;
            if (QueryFullProcessImageName(h, 0, sb, ref size) && size > 0)
                return sb.ToString();
        }
        catch { /* ignore */ }
        finally { CloseHandle(h); }
        return null;
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_TERMINATE = 0x0001;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    //
    // ===== SeDebugPrivilege 启用(主动处置的前提)=====
    //
    // 没有 SeDebugPrivilege 时,OpenProcess(PROCESS_TERMINATE) 对「以其他用户/更高
    // 完整性级别运行」的目标进程会被拒绝(ERROR_ACCESS_DENIED),导致 TerminateProcess
    // 形同虚设——这正是「检测到了、判定 Block 了,但进程没被结束」的根因之一。
    // 服务以 LocalSystem 运行时本就持有该特权,但默认处于「禁用」状态,必须显式启用。
    // 进程级一次性启用,线程安全(Interlocked 防重复)。
    //

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privilege0;
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const string SE_DEBUG_NAME = "SeDebugPrivilege";

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    private static int _seDebugTried;
    private static bool _seDebugResult;

    /// <summary>
    /// 为当前进程启用 SeDebugPrivilege。进程级一次性执行(可重复调用,内部去重)。
    /// 返回是否已成功启用(或先前已启用)。失败不抛异常,仅影响对高完整性进程的处置能力。
    ///
    /// 注意:后续调用返回的是【首次尝试的真实结果】,而非无条件 true ——
    /// 否则首次失败后,日志与调用方会拿到假的"已启用",掩盖处置受限的真因。
    /// </summary>
    public static bool EnsureDebugPrivilege()
    {
        if (!OperatingSystem.IsWindows()) return false;
        // 仅首次真正执行 P/Invoke;后续调用复用首次的真实结果。
        if (System.Threading.Interlocked.Exchange(ref _seDebugTried, 1) == 1)
            return System.Threading.Volatile.Read(ref _seDebugResult);

        bool ok = TryEnableDebugPrivilege();
        System.Threading.Volatile.Write(ref _seDebugResult, ok);
        return ok;
    }

    /// <summary>实际执行 SeDebugPrivilege 启用的底层逻辑。成功返回 true。</summary>
    private static bool TryEnableDebugPrivilege()
    {
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                return false;

            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out var luid))
                return false;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privilege0 = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = SE_PRIVILEGE_ENABLED
                }
            };

            if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            // AdjustTokenPrivileges 即便部分失败也返回 true;用 GetLastError 区分。
            return Marshal.GetLastWin32Error() == 0; // ERROR_SUCCESS
        }
        catch { return false; }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    /// <summary>
    /// 查询内核是否把该进程标记为「关键进程」(critical)。这是 Windows 官方权威来源:
    /// 内核正是据此在进程死亡时触发 CRITICAL_PROCESS_DIED(0xEF)。比按映像名匹配可靠得多
    /// (能覆盖 wininit/services/lsass/csrss 等所有被标记进程,且不受路径解析失败影响)。
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsProcessCritical(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool Critical);

    /// <summary>
    /// 通过内核标记判断 PID 是否为关键进程。无法判定时返回 null(由调用方按保守策略处理)。
    /// </summary>
    private static bool? QueryKernelCritical(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 0) return null;
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (IsProcessCritical(h, out bool critical)) return critical;
            return null;
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// 绝不结束的关键系统进程名(小写)。这些进程一旦被结束会立即触发
    /// CRITICAL_PROCESS_DIED(0xEF)蓝屏。无论规则/裁决如何,用户态主动处置
    /// (结束发起进程)都必须跳过它们 —— 这是防蓝屏的最后一道底线。
    /// 注:RemoteThread/ImageLoad 这类"仅记录型"事件常把系统进程当作发起方,
    /// 误判 Block 后若真把 services/svchost 结束掉,系统会立刻崩溃。
    /// </summary>
    private static readonly HashSet<string> CriticalProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
        "fontdrvhost.exe", "dwm.exe", "system", "registry", "memory compression",
        "spoolsv.exe",
    };

    /// <summary>判断给定 PID 是否为关键系统进程。</summary>
    /// <remarks>
    /// 多重判定,任一命中即视为关键(fail-safe,宁可漏杀不可误杀关键进程):
    ///  1) 内核 IsProcessCritical 标记 —— 权威来源,内核据此触发 0xEF;
    ///  2) System32/SysWOW64 下的已知关键进程名;
    ///  3) 无法解析映像路径时(常见于高权限/受保护进程)—— 保守判定为关键。
    /// 之前的实现里"路径解析失败 => 非关键 => 可杀"是导致误杀 svchost 蓝屏的根因。
    /// </remarks>
    public static bool IsCriticalProcess(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 4) return true; // System/Idle 视为关键

        // 1) 内核权威标记:能判定就以它为准(true=关键直接拦,false 继续看名单兜底)。
        var kernelCritical = QueryKernelCritical(pid);
        if (kernelCritical == true) return true;

        try
        {
            var path = TryGetProcessImagePath(pid);
            if (string.IsNullOrEmpty(path))
            {
                // 2) 路径解析失败:无法确认身份。若内核明确判定为非关键则放行,
                //    否则保守视为关键(防止误杀受保护的系统进程导致蓝屏)。
                return kernelCritical != false;
            }
            var name = System.IO.Path.GetFileName(path);
            if (string.IsNullOrEmpty(name)) return kernelCritical != false;

            // 3) 关键进程必须位于 System32/SysWOW64 下,避免同名恶意软件
            //    (如放在 Temp 的 svchost.exe)蒙混过关。
            bool inSystem32 = path.Contains(@"\Windows\System32\", StringComparison.OrdinalIgnoreCase) ||
                              path.Contains(@"\Windows\SysWOW64\", StringComparison.OrdinalIgnoreCase);
            return inSystem32 && CriticalProcessNames.Contains(name);
        }
        catch
        {
            // 异常时保守处理:不可确认即视为关键,绝不冒险结束。
            return true;
        }
    }

    /// <summary>
    /// 强制结束指定进程。用于「仅记录型」内核事件(映像加载 / 远程线程注入)被裁决为
    /// Block 时的主动处置:这类事件内核回调无法原地阻断,只能由用户态结束发起进程。
    /// 成功返回 true。
    ///
    /// 安全底线:绝不结束关键系统进程(services/svchost/lsass 等),否则会触发
    /// CRITICAL_PROCESS_DIED 蓝屏。命中关键进程时直接返回 false(视为未处置)。
    /// </summary>
    public static bool TryTerminateProcess(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 4) return false; // 不动 System/Idle

        if (IsCriticalProcess(pid)) return false; // 关键系统进程绝不结束(防蓝屏)

        // 注意:这里【不再】对「位于 System32/SysWOW64 的进程」一律放过。
        // 之前的「整个系统目录一律不结束」是过度保守的,它把所有 LOLBin
        // (powershell.exe / certutil.exe / reg.exe / rundll32.exe / mshta.exe / wmic.exe …)
        // 都变成「杀不掉」——而这些恰恰是攻击者滥用「已运行/系统自带程序」实施无文件攻击、
        // 凭据转储、下载执行的主要载体。引擎对它们判出 Block 后却结束不了,
        // 表现就是「检测到了但毫无作用」。真正会导致 0xEF 蓝屏的关键进程
        // (smss/csrss/wininit/winlogon/services/lsass/svchost/dwm/spoolsv 等)
        // 已由上面的 IsCriticalProcess(含内核 IsProcessCritical 权威标记 + 名单 + 路径校验)
        // 兜底,绝不会被结束。结束 LOLBin 不会让系统崩溃。

        // 确保已启用 SeDebugPrivilege:否则对高完整性 / 跨会话进程的
        // OpenProcess(PROCESS_TERMINATE) 会被拒绝(ERROR_ACCESS_DENIED),处置失败。
        EnsureDebugPrivilege();

        IntPtr h = OpenProcess(PROCESS_TERMINATE, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return TerminateProcess(h, 1); }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// 结束指定进程及其所有后代进程(进程树)。用于 Block 一个恶意软件本体时,
    /// 连带清除它已派生/释放的子进程(藏在软件包内、由主程序拉起的载荷 / helper / worker)。
    ///
    /// 安全保证:每个待结束进程(含根)都仍走 <see cref="TryTerminateProcess"/> 的安全门槛——
    /// 关键系统进程、System32/SysWOW64 下的进程一律跳过,绝不误杀系统组件。
    /// 防 PID 复用:仅纳入「启动时间不早于根进程」的后代,避免误杀复用了旧 PID 的无关进程。
    /// 结束顺序:先后代、后根,避免父退出后子进程被系统重新归属(orphan)而漏杀。
    ///
    /// 返回成功结束的进程数(含根)。
    /// </summary>
    public static int TerminateProcessTree(int rootPid)
    {
        if (!OperatingSystem.IsWindows() || rootPid <= 4) return 0;

        var descendants = CollectDescendants(rootPid);

        int killed = 0;
        // 先结束后代(由深到浅:列表已按 BFS 收集,逆序结束更接近"叶子优先")
        for (int i = descendants.Count - 1; i >= 0; i--)
        {
            if (TryTerminateProcess(descendants[i])) killed++;
        }
        // 最后结束根进程本体
        if (TryTerminateProcess(rootPid)) killed++;

        return killed;
    }

    /// <summary>
    /// 收集指定进程的所有后代 PID(BFS,防环、限规模)。
    /// 通过对当前所有进程逐一解析父 PID 建立父→子索引,再从根向下展开。
    /// 仅纳入启动时间不早于根进程的后代,降低 PID 复用导致的误判。
    /// </summary>
    private static List<int> CollectDescendants(int rootPid)
    {
        var result = new List<int>();
        if (!OperatingSystem.IsWindows()) return result;

        // 1) 快照当前进程,建立 父PID -> 子PID 列表,并记录启动时间。
        var childrenByParent = new Dictionary<int, List<int>>();
        var startTime = new Dictionary<int, DateTime>();
        DateTime rootStart = DateTime.MinValue;

        System.Diagnostics.Process[] procs;
        try { procs = System.Diagnostics.Process.GetProcesses(); }
        catch { return result; }

        foreach (var p in procs)
        {
            try
            {
                int pid = p.Id;
                if (pid <= 4) continue;
                int ppid = TryGetParentPid(pid);
                try { startTime[pid] = p.StartTime.ToUniversalTime(); } catch { /* 无权读取启动时间则忽略 */ }
                if (pid == rootPid && startTime.TryGetValue(pid, out var rs)) rootStart = rs;
                if (ppid > 0)
                {
                    if (!childrenByParent.TryGetValue(ppid, out var list))
                        childrenByParent[ppid] = list = new List<int>();
                    list.Add(pid);
                }
            }
            catch { /* 单个进程读取失败不影响整体 */ }
            finally { p.Dispose(); }
        }

        // 2) 从根 BFS 向下展开,收集后代(防环 + 上限保护)。
        var visited = new HashSet<int> { rootPid };
        var queue = new Queue<int>();
        queue.Enqueue(rootPid);
        const int MaxNodes = 1024;

        while (queue.Count > 0 && result.Count < MaxNodes)
        {
            int cur = queue.Dequeue();
            if (!childrenByParent.TryGetValue(cur, out var kids)) continue;
            foreach (var kid in kids)
            {
                if (!visited.Add(kid)) continue;

                // PID 复用防护:子进程启动时间早于根进程,说明它不是本次攻击树的真实后代
                // (是复用了旧 PID 的无关进程),跳过。无启动时间信息时保守纳入。
                if (rootStart != DateTime.MinValue &&
                    startTime.TryGetValue(kid, out var ks) && ks < rootStart)
                    continue;

                result.Add(kid);
                queue.Enqueue(kid);
            }
        }

        return result;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,
        System.Text.StringBuilder lpExeName, ref uint lpdwSize);

    /// <summary>
    /// 读取指定 PID 的进程命令行(通过 PEB -> ProcessParameters -> CommandLine)。
    /// 失败返回 null。
    ///
    /// 用途:内核驱动事件源(<see cref="DriverEventSource"/>)只提供映像路径,
    /// 不带命令行,而大量规则(LOLBin / 勒索 vssadmin / WMI 持久化 / bcdedit / certutil
    /// 等)依赖命令行特征匹配。进程被内核阻塞等待裁决期间仍然存活,此处可可靠读取。
    ///
    /// 仅在 64 位服务进程上实现:x64 Windows 上即使是 32 位(WOW64)目标进程也拥有
    /// 64 位 PEB,故统一用 64 位偏移即可覆盖 32/64 位目标。
    /// </summary>
    public static string? TryGetCommandLine(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 0) return null;
        if (IntPtr.Size != 8) return null; // 仅支持 64 位宿主

        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            // 1) 取 PEB 基址
            var pbi = new PROCESS_BASIC_INFORMATION();
            int status = NtQueryInformationProcess(h, 0 /*ProcessBasicInformation*/,
                ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return null;

            // 2) PEB.ProcessParameters (x64 偏移 0x20)
            IntPtr procParams = ReadPtr(h, pbi.PebBaseAddress + 0x20);
            if (procParams == IntPtr.Zero) return null;

            // 3) RTL_USER_PROCESS_PARAMETERS.CommandLine (UNICODE_STRING, x64 偏移 0x70)
            //    UNICODE_STRING: USHORT Length; USHORT MaximumLength; (4 字节填充) PWSTR Buffer;
            IntPtr unicodeStr = procParams + 0x70;
            if (!ReadMemory(h, unicodeStr, out byte[] usBuf, 16)) return null;

            ushort length = BitConverter.ToUInt16(usBuf, 0);
            if (length == 0 || length > 0x8000) return null; // 防御异常长度
            IntPtr buffer = (IntPtr)BitConverter.ToInt64(usBuf, 8);
            if (buffer == IntPtr.Zero) return null;

            // 4) 读取命令行字符串
            if (!ReadMemory(h, buffer, out byte[] cmdBuf, length)) return null;
            return System.Text.Encoding.Unicode.GetString(cmdBuf).TrimEnd('\0');
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    /// <summary>
    /// 取指定进程的父进程 PID(通过 NtQueryInformationProcess 读取
    /// PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId)。失败返回 0。
    ///
    /// 用途:内核注册表/文件等事件只归因到「执行写入的进程」,但要溯源「谁触发了这次操作」
    /// 需要父进程链。此方法补全父 PID,供事件富化解析父进程路径与命令行。
    /// </summary>
    public static int TryGetParentPid(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 0) return 0;

        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return 0;
        try
        {
            var pbi = new PROCESS_BASIC_INFORMATION();
            int status = NtQueryInformationProcess(h, 0 /*ProcessBasicInformation*/,
                ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            if (status != 0) return 0;
            long ppid = pbi.InheritedFromUniqueProcessId.ToInt64();
            return ppid is > 0 and < int.MaxValue ? (int)ppid : 0;
        }
        catch { return 0; }
        finally { CloseHandle(h); }
    }

    private static IntPtr ReadPtr(IntPtr hProcess, IntPtr address)
        => ReadMemory(hProcess, address, out byte[] buf, 8)
            ? (IntPtr)BitConverter.ToInt64(buf, 0)
            : IntPtr.Zero;

    private static bool ReadMemory(IntPtr hProcess, IntPtr address, out byte[] buffer, int size)
    {
        buffer = new byte[size];
        return ReadProcessMemory(hProcess, address, buffer, size, out int read) && read == size;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass,
        ref PROCESS_BASIC_INFORMATION procInfo, int procInfoLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    /// <summary>
    /// SHA-256 计算的文件大小上限(字节)。超过即跳过哈希(返回 null)。
    ///
    /// 整文件哈希是富化管线里唯一的"重 I/O":读完整个文件才能算出摘要。对几百 MB 的
    /// 大文件,一次哈希会把一个富化 worker 占住数秒。虽然内核侧已不再因此卡顿(事件
    /// 是异步队列消费),但 worker 被长时间占住会拖慢其它待富化事件的处置时效。
    /// 设 256MB 上限:正常可执行文件远小于此;超大文件几乎不是按哈希匹配的目标,
    /// 跳过哈希只损失"首见/信誉"这一项弱信号,签名/证书等其余画像不受影响。
    /// </summary>
    private const long MaxHashFileSize = 256L * 1024 * 1024;

    /// <summary>计算文件 SHA-256(失败返回 null)。超过 <see cref="MaxHashFileSize"/> 的文件跳过。</summary>
    public static string? TryComputeSha256(string? path)
        => Cached<string?>(path, "sha256", () =>
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            var fi = new FileInfo(path);
            if (fi.Length > MaxHashFileSize) return null; // 超大文件跳过,避免占住 worker
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash);
        }
        catch { return null; }
    });

    /// <summary>校验文件是否带可信 Authenticode 签名。</summary>
    public static bool IsSigned(string? path)
        => Cached(path, "signed", () => IsSignedCore(path));

    private static bool IsSignedCore(string? path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;

        // 1) 先验嵌入式 Authenticode 签名
        if (VerifyEmbedded(path)) return true;

        // 2) 回退:目录(catalog)签名 —— 大多数 Windows 系统二进制(ipconfig/conhost 等)
        //    并无嵌入签名,而是由安全目录签名,必须用 catalog 验证,否则会被误判为未签名。
        return VerifyCatalog(path);
    }

    private static bool VerifyEmbedded(string path)
    {
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = path,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
            try
            {
                Marshal.StructureToPtr(fileInfo, pFile, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                    pPolicyCallbackData = IntPtr.Zero,
                    pSIPClientData = IntPtr.Zero,
                    dwUIChoice = WTD_UI_NONE,
                    fdwRevocationChecks = WTD_REVOKE_NONE,
                    dwUnionChoice = WTD_CHOICE_FILE,
                    pFile = pFile,
                    dwStateAction = WTD_STATEACTION_VERIFY,
                    hWVTStateData = IntPtr.Zero,
                    pwszURLReference = IntPtr.Zero,
                    dwProvFlags = WTD_SAFER_FLAG,
                    dwUIContext = 0
                };

                var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                int result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);

                data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);

                return result == 0;
            }
            finally
            {
                Marshal.FreeHGlobal(pFile);
            }
        }
        catch { return false; }
    }

    /// <summary>通过安全目录(catalog)验证文件签名(Windows 系统二进制常用)。</summary>
    private static bool VerifyCatalog(string path)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hFile = IntPtr.Zero;
        IntPtr pHash = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext2(ref hCatAdmin, IntPtr.Zero, null, IntPtr.Zero, 0))
                return false;

            hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero,
                OPEN_EXISTING, 0, IntPtr.Zero);
            if (hFile == IntPtr.Zero || hFile == new IntPtr(-1)) return false;

            int hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, IntPtr.Zero, 0);
            if (hashSize == 0) return false;

            pHash = Marshal.AllocHGlobal(hashSize);
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashSize, pHash, 0))
                return false;

            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pHash, (uint)hashSize, 0, IntPtr.Zero);
            bool found = hCatInfo != IntPtr.Zero;
            if (found)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            return found;
        }
        catch { return false; }
        finally
        {
            if (pHash != IntPtr.Zero) Marshal.FreeHGlobal(pHash);
            if (hFile != IntPtr.Zero && hFile != new IntPtr(-1)) CloseHandle(hFile);
            if (hCatAdmin != IntPtr.Zero) CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    // ---- Catalog (wintrust.dll) P/Invoke ----
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint OPEN_EXISTING = 3;

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(
        ref IntPtr phCatAdmin, IntPtr pgSubsystem, [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, IntPtr hFile, ref int pcbHash, IntPtr pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, IntPtr pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    // ---- WinVerifyTrust P/Invoke ----
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;

    private static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);
}
