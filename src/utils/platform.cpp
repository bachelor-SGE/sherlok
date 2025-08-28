#include "platform.h"

#include <sstream>
#include <vector>
#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#elif defined(__linux__)
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

namespace utils {

OperatingSystem detectOperatingSystem() {
#ifdef _WIN32
    return OperatingSystem::Windows;
#elif defined(__APPLE__)
    return OperatingSystem::MacOS;
#elif defined(__linux__)
    return OperatingSystem::Linux;
#else
    return OperatingSystem::Unknown;
#endif
}

std::string getOperatingSystemName() {
    switch (detectOperatingSystem()) {
    case OperatingSystem::Windows: return "Windows";
    case OperatingSystem::MacOS: return "macOS";
    case OperatingSystem::Linux: return "Linux";
    default: return "Unknown";
    }
}

std::string getExecutablePath() {
#ifdef _WIN32
    wchar_t pathW[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, pathW, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return std::string();
    int u8Len = WideCharToMultiByte(CP_UTF8, 0, pathW, (int)len, nullptr, 0, nullptr, nullptr);
    std::string pathUtf8; pathUtf8.resize(u8Len);
    WideCharToMultiByte(CP_UTF8, 0, pathW, (int)len, &pathUtf8[0], u8Len, nullptr, nullptr);
    return pathUtf8;
#else
    char buf[4096];
#if defined(__APPLE__)
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        return std::string(buf);
    }
    return std::string();
#elif defined(__linux__)
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        return std::string(buf);
    }
    return std::string();
#else
    return std::string();
#endif
#endif
}

static bool ensureAutostartWindows() {
#ifdef _WIN32
    wchar_t exePath[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return false;
    }

    PWSTR startupPath = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Startup, 0, nullptr, &startupPath);
    if (FAILED(hr) || !startupPath) {
        if (startupPath) CoTaskMemFree(startupPath);
        return false;
    }

    std::wstring lnkPath = std::wstring(startupPath) + L"\\FileEncryptionDemo.lnk";
    CoTaskMemFree(startupPath);

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellLinkW* psl = nullptr;
    hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
    if (FAILED(hr) || !psl) {
        CoUninitialize();
        return false;
    }
    psl->SetPath(exePath);
    psl->SetDescription(L"File Encryption Demo");
    psl->SetShowCmd(SW_SHOWNORMAL);

    IPersistFile* ppf = nullptr;
    hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        hr = ppf->Save(lnkPath.c_str(), TRUE);
        ppf->Release();
    }
    psl->Release();
    CoUninitialize();
    return SUCCEEDED(hr);
#else
    return false;
#endif
}

static std::string getHomeDir() {
#if defined(_WIN32)
    return std::string();
#else
    const char* home = getenv("HOME");
    if (home && *home) return std::string(home);
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) return std::string(pw->pw_dir);
    return std::string();
#endif
}

static bool writeTextFile(const std::string& path, const std::string& content) {
    FILE* f = fopen(path.c_str(), "w");
    if (!f) return false;
    size_t n = fwrite(content.data(), 1, content.size(), f);
    fclose(f);
    return n == content.size();
}

static bool ensureAutostartLinux() {
#if defined(__linux__)
    std::string exe = getExecutablePath();
    if (exe.empty()) return false;
    std::string home = getHomeDir();
    if (home.empty()) return false;
    std::string dir = home + "/.config/autostart";
    // try create directory
    (void)system((std::string("mkdir -p ") + dir).c_str());
    std::string desktop = dir + "/file-encryption-demo.desktop";
    std::ostringstream oss;
    oss << "[Desktop Entry]\n";
    oss << "Type=Application\n";
    oss << "Name=File Encryption Demo\n";
    oss << "Exec=" << exe << "\n";
    oss << "X-GNOME-Autostart-enabled=true\n";
    return writeTextFile(desktop, oss.str());
#else
    return false;
#endif
}

static bool ensureAutostartMac() {
#if defined(__APPLE__)
    // Simple LaunchAgent plist in ~/Library/LaunchAgents
    std::string exe = getExecutablePath();
    if (exe.empty()) return false;
    std::string home = getHomeDir();
    if (home.empty()) return false;
    std::string dir = home + "/Library/LaunchAgents";
    (void)system((std::string("mkdir -p ") + dir).c_str());
    std::string plistPath = dir + "/com.fileencryption.demo.plist";
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        << "<plist version=\"1.0\">\n"
        << "<dict>\n"
        << "  <key>Label</key><string>com.fileencryption.demo</string>\n"
        << "  <key>ProgramArguments</key>\n"
        << "  <array>\n"
        << "    <string>" << exe << "</string>\n"
        << "  </array>\n"
        << "  <key>RunAtLoad</key><true/>\n"
        << "</dict>\n"
        << "</plist>\n";
    bool ok = writeTextFile(plistPath, oss.str());
    // load it (non-blocking, ignore errors)
    (void)system((std::string("launchctl load -w ") + plistPath + " 2>/dev/null").c_str());
    return ok;
#else
    return false;
#endif
}

bool ensureAutostart() {
    switch (detectOperatingSystem()) {
    case OperatingSystem::Windows:
        return ensureAutostartWindows();
    case OperatingSystem::Linux:
        return ensureAutostartLinux();
    case OperatingSystem::MacOS:
        return ensureAutostartMac();
    default:
        return false;
    }
}

}


