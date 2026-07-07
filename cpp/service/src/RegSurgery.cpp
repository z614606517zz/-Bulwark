#include "bulwark/service/RegSurgery.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>

namespace bulwark::service {
namespace {

HKEY hiveToHkey(RegHive h) {
    switch (h) {
        case RegHive::LocalMachine:  return HKEY_LOCAL_MACHINE;
        case RegHive::CurrentUser:   return HKEY_CURRENT_USER;
        case RegHive::ClassesRoot:   return HKEY_CLASSES_ROOT;
        case RegHive::Users:         return HKEY_USERS;
        case RegHive::CurrentConfig: return HKEY_CURRENT_CONFIG;
    }
    return HKEY_LOCAL_MACHINE;
}

REGSAM viewToSam(RegView v) {
    switch (v) {
        case RegView::Registry32: return KEY_WOW64_32KEY;
        case RegView::Registry64: return KEY_WOW64_64KEY;
        default:                  return 0;
    }
}

const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

// Enable a privilege in the current process token (best-effort; silent on failure).
void enablePrivilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    }
    CloseHandle(token);
}

// Fill caller buffer with the BUILTIN\Administrators SID; returns PSID or nullptr.
PSID buildAdminsSid(BYTE* buf, DWORD bufSize) {
    DWORD sz = bufSize;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, buf, &sz)) return nullptr;
    return reinterpret_cast<PSID>(buf);
}

void takeOwnership(HKEY root, const QString& subKey, REGSAM sam, PSID admins) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, WRITE_OWNER | sam, &hk) == ERROR_SUCCESS) {
        SetSecurityInfo(hk, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
                        admins, nullptr, nullptr, nullptr);
        RegCloseKey(hk);
    }
}

void grantAdminsFullControl(HKEY root, const QString& subKey, REGSAM sam,
                            PSID admins, DWORD inheritance) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, wstr(subKey), 0, READ_CONTROL | WRITE_DAC | sam, &hk) != ERROR_SUCCESS)
        return;
    PACL oldDacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetSecurityInfo(hk, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                        nullptr, nullptr, &oldDacl, nullptr, &sd) == ERROR_SUCCESS) {
        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = KEY_ALL_ACCESS;
        ea.grfAccessMode = SET_ACCESS;
        ea.grfInheritance = inheritance;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admins);
        PACL newDacl = nullptr;
        if (SetEntriesInAclW(1, &ea, oldDacl, &newDacl) == ERROR_SUCCESS) {
            SetSecurityInfo(hk, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                            nullptr, nullptr, newDacl, nullptr);
            if (newDacl) LocalFree(newDacl);
        }
        if (sd) LocalFree(sd);
    }
    RegCloseKey(hk);
}

} // namespace
} // namespace bulwark::service

namespace bulwark::service {
namespace RegSurgery {

bool forceDeleteValue(RegHive hive, const QString& subKey, const QString& valueName, RegView view) {
    enablePrivilege(L"SeTakeOwnershipPrivilege");
    enablePrivilege(L"SeRestorePrivilege");

    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    PSID admins = buildAdminsSid(sidBuf, sizeof(sidBuf));
    const HKEY root = hiveToHkey(hive);
    const REGSAM sam = viewToSam(view);

    if (admins) {
        takeOwnership(root, subKey, sam, admins);          // step 1
        grantAdminsFullControl(root, subKey, sam, admins, NO_INHERITANCE); // step 2
    }

    HKEY hk = nullptr; // step 3: delete the value
    if (RegOpenKeyExW(root, wstr(subKey), 0, KEY_SET_VALUE | sam, &hk) != ERROR_SUCCESS)
        return false;
    const LSTATUS st = RegDeleteValueW(hk, wstr(valueName));
    RegCloseKey(hk);
    return st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND; // missing == success
}

bool forceDeleteSubKeyTree(RegHive hive, const QString& parentSubKey,
                           const QString& childName, RegView view) {
    enablePrivilege(L"SeTakeOwnershipPrivilege");
    enablePrivilege(L"SeRestorePrivilege");

    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
    PSID admins = buildAdminsSid(sidBuf, sizeof(sidBuf));
    const HKEY root = hiveToHkey(hive);
    const REGSAM sam = viewToSam(view);
    const QString childPath = parentSubKey + QStringLiteral("\\") + childName;

    if (admins) {
        takeOwnership(root, childPath, sam, admins);
        grantAdminsFullControl(root, childPath, sam, admins, CONTAINER_INHERIT_ACE);
    }

    HKEY parent = nullptr;
    if (RegOpenKeyExW(root, wstr(parentSubKey), 0, KEY_ALL_ACCESS | sam, &parent) != ERROR_SUCCESS)
        return false;
    const LSTATUS st = RegDeleteTreeW(parent, wstr(childName));
    RegCloseKey(parent);
    return st == ERROR_SUCCESS || st == ERROR_FILE_NOT_FOUND;
}

} // namespace RegSurgery
} // namespace bulwark::service
