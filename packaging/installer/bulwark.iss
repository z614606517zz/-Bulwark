; =====================================================================
;  磐垒主动防御 (Bulwark HIPS) —— Inno Setup 安装脚本
;
;  产物:单个 Bulwark-Setup-<版本>.exe,标准安装向导(欢迎 / 许可 / 选择目录 /
;  附加任务 / 准备安装 / 进度 / 完成),自带卸载程序并登记到「应用和功能」。
;
;  用 scripts\make-installer.ps1 编译,不要直接双击本文件:那个脚本会先把载荷
;  分拣到暂存目录、给两个 exe 签名、核对版本号与钉死的签名者指纹,然后才调 ISCC,
;  最后再给 Setup.exe 本身签名。少了那些前置步骤,编出来的包在目标机上会被
;  install.ps1 自己的载荷校验拒掉。
;
;  ── 职责划分(本文件最重要的一段)──────────────────────────────────
;  Inno 只做它擅长的:向导界面、UAC 提权、把文件解压到安装目录、快捷方式、
;  「应用和功能」条目、卸载程序。
;  「和系统打交道」的部分全部交给 install.ps1 / uninstall.ps1 —— 那里每一条顺序
;  都是踩出来的,用 Pascal 重写一遍等于把踩过的坑再踩一次:
;    · 先停服务再卸驱动(驱动在载时本产品进程受内核自我保护,外部杀不掉);
;    · 卸驱动必须早于 sc delete(内核注册表硬拦含 "\Services\Bulwark");
;    · 用户态服务的注册要在强杀之前删掉(否则 SCM 的失败恢复策略 5 秒后把它拉回来);
;    · 驱动只在目标机已处于测试签名模式时才加载,否则只部署 + 注册。
;
;  唯一在 Pascal 里做的系统操作是「解压之前先把旧版本停下来」,因为它必须发生在
;  Inno 复制文件【之前】:旧服务还在跑就锁着自己的 exe,复制必然失败。那一步只用
;  sc / fltmc / taskkill,不需要脚本,所以没必要为它往 {tmp} 放一个 .ps1。
;
;  ── 语言 ──────────────────────────────────────────────────────────
;  Inno 6 官方不带简体中文。Languages\ChineseSimplified.isl 取自社区翻译
;  (github.com/kira-96/Inno-Setup-Chinese-Simplified-Translation),它只是一份
;  key=value 的界面文案表,不含任何可执行内容。make-installer.ps1 编译前会检查
;  它在不在,不在就退回纯英文界面,而不是编出一个半中半英的包。
; =====================================================================

#ifndef AppVersion
  #define AppVersion "1.0.3"
#endif
#ifndef PayloadDir
  #error PayloadDir must be passed with /DPayloadDir=<staged app dir>
#endif
#ifndef SrcDir
  #error SrcDir must be passed with /DSrcDir=<packaging\installer dir>
#endif
#ifndef OutDir
  #error OutDir must be passed with /DOutDir=<output dir>
#endif
#ifndef HasChinese
  #define HasChinese "0"
#endif

#define AppName "磐垒主动防御"
#define AppNameFull "磐垒主动防御 (Bulwark HIPS)"
#define AppPublisher "Bulwark"
#define DriverService "Bulwark"
#define UserService "BulwarkService"

[Setup]
; AppId 是升级与卸载识别的唯一依据,一旦发布就不能再改 —— 改了会让已装的旧版本
; 变成一条新包认不出来的孤立条目,用户会在「应用和功能」里看到两个磐垒。
AppId={{8F3C4A21-5B7E-4D96-9C18-2A6E5B0D77F1}
AppName={#AppNameFull}
AppVersion={#AppVersion}
AppVerName={#AppNameFull} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppNameFull} 安装程序
VersionInfoProductName={#AppNameFull}
VersionInfoCopyright=Copyright (C) 2026 {#AppPublisher}

DefaultDirName={autopf}\Bulwark
DefaultGroupName={#AppName}
; 目录页保留(确实有人要装到别的盘);开始菜单文件夹名这一页去掉 —— 多一页
; 只多一次犹豫,而这个名字没人会想改。
DisableWelcomePage=no
DisableDirPage=no
DisableProgramGroupPage=yes
DisableReadyPage=no
AllowNoIcons=yes

LicenseFile={#SrcDir}\许可与风险须知.txt
OutputDir={#OutDir}
OutputBaseFilename=Bulwark-Setup-{#AppVersion}
SetupIconFile={#PayloadDir}\app.ico
UninstallDisplayIcon={app}\bulwark_ui.exe
UninstallDisplayName={#AppNameFull}

Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

; 带两种语言时 Inno 默认先弹一个「选择安装语言」小框。关掉它,让 Inno 按系统区域
; 自己挑(中文系统进中文,其他进英文)。多这一步没有信息量:许可与说明本来只有
; 中文一份,真正需要英文界面的人也不会因为少一个下拉框而装不上。
ShowLanguageDialog=no

; 内核驱动 + Program Files + 服务注册,全都要管理员;不给降权运行的余地。
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

; 【刻意关掉 Inno 的「文件被占用」自动处理】。它走重启管理器,会尝试关掉占用文件
; 的进程 —— 对象正好是本产品的服务,而那个服务受内核自我保护,外部的结束请求会
; 静默失败:Inno 以为关掉了、实际没关,复制照样失败,而报错完全指不到真实原因。
; 停旧版本这件事由 PrepareToInstall 里那段按正确顺序自己做。
CloseApplications=no
RestartApplications=no

[Languages]
#if HasChinese == "1"
Name: "cn"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
#endif
Name: "en"; MessagesFile: "compiler:Default.isl"

[Messages]
#if HasChinese == "1"
cn.WelcomeLabel2=即将在这台计算机上安装 [name/ver]。%n%n这是一套含【内核驱动】的主动防御软件。内核驱动出错会导致蓝屏,首次安装请优先在带快照的测试机或虚拟机上验证。%n%n建议先关闭其他正在运行的程序。
cn.FinishedLabel=安装完成。%n%n防护是否进入「内核前拦截」形态,取决于这台机器是否处于测试签名模式 —— 开始菜单里的「系统体检」会逐项告诉你当前真实形态。
cn.FinishedLabelNoIcons=安装完成。%n%n防护是否进入「内核前拦截」形态,取决于这台机器是否处于测试签名模式 —— 安装目录里的 体检.bat 会逐项告诉你当前真实形态。
#endif
en.WelcomeLabel2=This will install [name/ver] on your computer.%n%nThis is a host intrusion prevention system that includes a KERNEL DRIVER. A fault in kernel code causes a bugcheck (BSOD), so validate the first install on a snapshotted test machine or VM.%n%nIt is recommended that you close all other applications before continuing.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
; 这一项改动机器全局的启动设置,所以默认不勾,并且把代价写进描述里。
; 已经处于测试签名模式时整项隐藏 —— 给一个「开启已经开着的东西」的勾选框,只会
; 让人以为自己需要重启。
Name: "testsigning"; Description: "开启测试签名模式,让内核驱动能够加载(会改动系统启动设置,需要重启一次)"; GroupDescription: "内核驱动:"; Flags: unchecked; Check: NeedTestSigningTask
Name: "bootstart"; Description: "内核驱动随系统启动加载(消除开机后到服务启动前的防护空窗)"; GroupDescription: "内核驱动:"; Flags: unchecked

[Files]
; 载荷。recursesubdirs 覆盖 platforms\ styles\ imageformats\ networkinformation\ tls\。
; ignoreversion:Qt 的 DLL 版本号不总是单调,按版本比对会出现「新包反而装不上去」。
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; 系统集成脚本随包装进安装目录(而不是丢在 {tmp} 用完即弃),三个理由:
;   1) 卸载时要用同一份逻辑,放 {tmp} 就得再放一次;
;   2) 用户态规则引擎把「安装目录里的 bulwark.ps1」列入维护脚本白名单,从安装
;      目录调用不会被自己的引擎当成「可疑目录里的 PowerShell」计分;
;   3) 出问题时这些文件就在安装目录里,能原样复现安装程序做过的每一步。
Source: "{#SrcDir}\install.ps1";       DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\安装说明.txt";        DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\许可与风险须知.txt";   DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\bulwark_ui.exe"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Comment: "{#AppNameFull}"
Name: "{group}\系统体检"; Filename: "{app}\体检.bat"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Comment: "只读地检查当前防护形态与安装状态"
Name: "{group}\收集诊断日志"; Filename: "{app}\收集日志.bat"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Comment: "把排查需要的信息打包到桌面(自动脱敏)"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\bulwark_ui.exe"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Tasks: desktopicon

[Run]
; 系统集成:部署并注册内核驱动、按条件加载、注册并启动后台服务、写安装痕迹。
; waituntilterminated 是必须的 —— 「完成」页上那个启动界面的选项依赖服务已经起来。
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install.ps1"" -SystemOnly -NoLaunch -Dir ""{app}"" {code:ExtraSetupArgs}"; \
  WorkingDir: "{app}"; StatusMsg: "正在部署内核驱动与后台服务(可能需要十几秒)…"; \
  Flags: runhidden waituntilterminated; Check: DoSystemIntegration

; runasoriginaluser:界面是常驻托盘的程序,没有理由长期以管理员身份跑;而且它
; 首次运行会往 HKCU 写登录自启项,以管理员身份跑会把那条写到执行安装的管理员
; 账户下,而不是当前登录用户。
Filename: "{app}\bulwark_ui.exe"; Description: "{cm:LaunchProgram,{#AppName}}"; \
  WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; 在 Inno 删文件之前跑:停界面与服务、卸驱动、删两个服务注册、删 System32 里的
; .sys、按安装痕迹回滚证书与测试签名、清各用户的登录自启项。
; 数据目录删不删由下面的 Pascal 问过用户后用参数传进来 —— 这里是 runhidden,
; 脚本里的 Read-Host 没有可交互的控制台,问了也没人能答。
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall.ps1"" -SystemOnly -Dir ""{app}"" {code:UninstallDataArg}"; \
  WorkingDir: "{app}"; RunOnceId: "BulwarkSystemCleanup"; \
  Flags: runhidden waituntilterminated; Check: DoSystemIntegration

[Code]
var
  TsChecked: Boolean;
  TsValue: Boolean;
  PurgeData: Boolean;
  PurgeDataAsked: Boolean;

{ ---- 测试签名模式是否已开启 ---------------------------------------------
  没有一个干净的注册表值可读,所以直接问 bcdedit。中文系统上它输出「是/否」,
  英文系统是 Yes/No,两种都要认 —— 只认 Yes 会让中文系统永远判成「未开启」,
  于是向导会去推荐那个需要重启的任务,白让用户重启一次。 }
function IsTestSigningOn(): Boolean;
var
  ResultCode, I: Integer;
  Output: TExecOutput;
  Line: String;
begin
  if not TsChecked then begin
    TsChecked := True;
    TsValue := False;
    if ExecAndCaptureOutput(ExpandConstant('{sys}\bcdedit.exe'), '/enum {current}', '',
                            SW_HIDE, ewWaitUntilTerminated, ResultCode, Output) then begin
      for I := 0 to GetArrayLength(Output.StdOut) - 1 do begin
        Line := Lowercase(Trim(Output.StdOut[I]));
        if Pos('testsigning', Line) > 0 then
          if (Pos('yes', Line) > 0) or (Pos('是', Line) > 0) then
            TsValue := True;
      end;
    end;
  end;
  Result := TsValue;
end;

function NeedTestSigningTask(): Boolean;
begin
  Result := not IsTestSigningOn();
end;

function IsSecureBootOn(): Boolean;
var
  V: Cardinal;
begin
  Result := False;
  if RegQueryDWordValue(HKEY_LOCAL_MACHINE,
       'SYSTEM\CurrentControlSet\Control\SecureBoot\State', 'UEFISecureBootEnabled', V) then
    Result := (V = 1);
end;

{ 注意这读的是【配置值】,不是运行状态 —— 运行状态要查 WMI 的 Win32_DeviceGuard,
  那在向导里不值得引入。权威判定由 install.ps1 做(它查的就是运行状态),这里只
  用来在「准备安装」页上给一句提前预警。 }
function IsHvciConfigured(): Boolean;
var
  V: Cardinal;
begin
  Result := False;
  if RegQueryDWordValue(HKEY_LOCAL_MACHINE,
       'SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity',
       'Enabled', V) then
    Result := (V = 1);
end;

{ ---- /NOSYSTEM=1:只解压,不碰系统 --------------------------------------
  存在的理由是「可验证性」。这个包会装内核驱动、注册 SYSTEM 服务、动全局的证书
  与启动设置 —— 想确认「解压和向导本身是对的」,不应该被迫先把这些都做一遍。
  带上这个开关时,[Run] 与 [UninstallRun] 里那两次系统集成整个跳过,只做文件
  的解压与删除。

    Bulwark-Setup-x.y.z.exe /VERYSILENT /NOSYSTEM=1 /DIR="%TEMP%\bwtest" /NOICONS /TASKS=""
    "%TEMP%\bwtest\unins000.exe" /VERYSILENT /NOSYSTEM=1

  刻意不在界面上暴露成一个复选框:正常安装的人没有理由选它,而一个「装了但什么
  都没接上」的状态从界面上看不出来,放出去只会制造「装完了却没防护」的疑难。 }
function DoSystemIntegration(): Boolean;
begin
  Result := (ExpandConstant('{param:NOSYSTEM|0}') = '0');
end;

{ 传给 install.ps1 的附加参数,来自用户在「附加任务」页上的选择。 }
function ExtraSetupArgs(Param: String): String;
begin
  Result := '';
  if WizardIsTaskSelected('testsigning') then
    Result := Result + ' -EnableTestSigning';
  if WizardIsTaskSelected('bootstart') then
    Result := Result + ' -BootStart';
end;

{ ---- 「准备安装」页上如实写清驱动会被怎么处置 --------------------------
  这是整个向导里唯一「动手之前把要做的事摆出来」的地方,而本产品最容易被误解的
  恰恰是这一条:装完之后到底有没有内核前拦截。含糊过去,用户会以为自己拿到了
  完整形态。 }
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  S: String;
begin
  S := '';
  if MemoDirInfo <> '' then S := S + MemoDirInfo + NewLine + NewLine;
  if MemoTasksInfo <> '' then S := S + MemoTasksInfo + NewLine + NewLine;

  S := S + '内核驱动:' + NewLine;
  if IsSecureBootOn() then begin
    S := S + Space + '仅部署并注册,不加载 —— Secure Boot 已开启,它开着时测试签名完全无效。' + NewLine;
    S := S + Space + '需进 BIOS/UEFI 关闭 Secure Boot 并重启,驱动才可能加载。' + NewLine;
  end else if IsHvciConfigured() then begin
    S := S + Space + '仅部署并注册,不加载 —— 内存完整性(HVCI)已启用,它会让测试签名失效。' + NewLine;
    S := S + Space + '需在「Windows 安全中心 > 设备安全性 > 内核隔离」关闭并重启。' + NewLine;
  end else if IsTestSigningOn() then begin
    S := S + Space + '部署 + 注册 + 立即加载(本机已处于测试签名模式)。' + NewLine;
    S := S + Space + '装完即可拿到行为前拦截。' + NewLine;
  end else if WizardIsTaskSelected('testsigning') then begin
    S := S + Space + '部署 + 注册,并开启测试签名模式 —— 需要重启一次才生效。' + NewLine;
    S := S + Space + '重启后后台服务会自动把驱动加载上来,不用再跑安装程序。' + NewLine;
  end else begin
    S := S + Space + '仅部署并注册,不加载 —— 本机未开启测试签名模式。' + NewLine;
    S := S + Space + '防护照样开启,但降级为用户态强制:能事后处置,拦不住「行为前」。' + NewLine;
    S := S + Space + '以后开启测试签名并重启,驱动会自动加载,不用重装。' + NewLine;
  end;
  Result := S;
end;

{ ---- 服务是否已停 --------------------------------------------------------
  sc query 在服务不存在时输出含 1060;存在时状态行里有 STOPPED / RUNNING 之类的
  英文常量(这一列不本地化,所以可以按串认)。 }
function ServiceIsStopped(const Name: String): Boolean;
var
  ResultCode, I: Integer;
  Output: TExecOutput;
  Line: String;
begin
  Result := True;
  if ExecAndCaptureOutput(ExpandConstant('{sys}\sc.exe'), 'query ' + Name, '',
                          SW_HIDE, ewWaitUntilTerminated, ResultCode, Output) then begin
    for I := 0 to GetArrayLength(Output.StdOut) - 1 do begin
      Line := Uppercase(Output.StdOut[I]);
      if Pos('1060', Line) > 0 then Exit;            { 服务不存在 = 已停 }
      if Pos('STATE', Line) > 0 then begin
        if Pos('STOPPED', Line) > 0 then Result := True
        else Result := False;
        Exit;
      end;
    end;
  end;
end;

{ ---- 解压之前把旧版本停下来 --------------------------------------------
  顺序与 install.ps1 里那段一致,理由见本文件头部。 }
procedure StopExistingBulwark();
var
  ResultCode, I: Integer;
  Sys: String;
begin
  Sys := ExpandConstant('{sys}');

  { 1) 先请服务控制器正常停止。绝不能一上来就杀:服务配了失败自动恢复策略,
       被杀会被判为异常终止,SCM 五秒后把它拉回来,然后继续锁着文件。 }
  Exec(Sys + '\sc.exe', 'stop {#UserService}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  for I := 1 to 30 do begin
    if ServiceIsStopped('{#UserService}') then Break;
    Sleep(1000);
  end;

  { 2) 卸内核驱动。它一走,自我保护随之解除,下面才杀得掉本产品自己的进程。 }
  Exec(Sys + '\fltmc.exe', 'unload {#DriverService}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sys + '\sc.exe', 'stop {#DriverService}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);

  { 3) 残留进程。到这一步已经没有内核自我保护挡着。 }
  Exec(Sys + '\taskkill.exe', '/F /IM bulwark_ui.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(Sys + '\taskkill.exe', '/F /IM bulwark_service.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1500);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  StopExistingBulwark();
end;

{ ---- 卸载时问一次数据目录 ----------------------------------------------
  %ProgramData%\Bulwark 里是用户攒下来的规则、审计日志,以及隔离区里的【真实
  恶意样本】。删掉不可恢复,所以默认保留、只问一句。 }
function UninstallDataArg(Param: String): String;
begin
  if not PurgeDataAsked then begin
    PurgeDataAsked := True;
    PurgeData := False;
    if DirExists(ExpandConstant('{commonappdata}\Bulwark')) then begin
      if MsgBox('是否同时删除磐垒的数据目录?' + #13#10#13#10 +
                ExpandConstant('{commonappdata}\Bulwark') + #13#10#13#10 +
                '里面有你的自定义规则、审计日志,以及隔离区里的真实恶意样本。' + #13#10 +
                '删除不可恢复。' + #13#10#13#10 +
                '选「否」将保留这些数据(推荐)。',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        PurgeData := True;
    end;
  end;
  if PurgeData then
    Result := '-PurgeData'
  else
    Result := '-KeepData';
end;
