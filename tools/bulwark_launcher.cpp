// Bulwark Launcher - 自动管理驱动和服务的启动器
// 编译: cl /EHsc /Fe:bulwark_launcher.exe bulwark_launcher.cpp /link advapi32.lib

#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

// 启动/停止驱动
bool ControlDriver(const std::wstring& serviceName, DWORD control) {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE service = OpenService(scm, serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    bool result = false;
    if (control == SERVICE_CONTROL_STOP) {
        SERVICE_STATUS status;
        result = ControlService(service, SERVICE_CONTROL_STOP, &status);
    } else {
        result = StartService(service, 0, nullptr);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return result;
}

// 启动进程
HANDLE StartProcess(const std::wstring& exePath, bool wait = false, bool hide = false) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    if (hide) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }

    std::wstring cmdLine = L"\"" + exePath + L"\"";
    if (!CreateProcessW(nullptr, &cmdLine[0], nullptr, nullptr, FALSE, 
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return nullptr;
    }

    if (wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        return pi.hProcess;
    }

    CloseHandle(pi.hThread);
    return pi.hProcess;
}

// 等待进程结束
void WaitForProcess(HANDLE hProcess) {
    if (hProcess) {
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
    }
}

// 终止进程
void TerminateProcessByName(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 获取当前目录
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring exeDir(exePath);
    exeDir = exeDir.substr(0, exeDir.find_last_of(L"\\/"));

    std::wstring servicePath = exeDir + L"\\bulwark_service.exe";
    std::wstring uiPath = exeDir + L"\\bulwark_ui.exe";

    // 1. 启动驱动
    ControlDriver(L"Bulwark", 0);
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // 2. 启动服务（后台）
    HANDLE hService = StartProcess(servicePath, false, true);
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // 3. 启动 UI（前台）
    HANDLE hUI = StartProcess(uiPath, false, false);

    // 4. 等待 UI 关闭
    WaitForProcess(hUI);

    // 5. 清理：停止服务
    TerminateProcessByName(L"bulwark_service.exe");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // 6. 停止驱动
    ControlDriver(L"Bulwark", SERVICE_CONTROL_STOP);

    return 0;
}
