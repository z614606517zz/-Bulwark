' Bulwark 静默启动脚本（完全无窗口）
' 双击即可运行，不显示任何控制台窗口

Set WshShell = CreateObject("WScript.Shell")

' 获取脚本所在目录
scriptDir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

' 构建 PowerShell 命令
psCommand = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command """ & _
    "sc.exe start Bulwark; " & _
    "Start-Sleep -Seconds 2; " & _
    "$wshell = New-Object -ComObject WScript.Shell; " & _
    "$wshell.Run('" & scriptDir & "\cpp\dist\bulwark_service.exe', 0, $false); " & _
    "Start-Sleep -Seconds 2; " & _
    "Start-Process -FilePath '" & scriptDir & "\cpp\dist\bulwark_ui.exe' -WorkingDirectory '" & scriptDir & "\cpp\dist'"""

' 以隐藏方式运行 PowerShell
WshShell.Run psCommand, 0, False
