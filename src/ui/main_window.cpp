#include "main_window.h"
#include <iostream>
#include <algorithm>
#include <string>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>

namespace {

struct PasswordDialogContext {
    std::wstring title;
    std::wstring message;
    std::wstring passwordWide;
    HWND editHandle = nullptr;
    HWND okButtonHandle = nullptr;
    bool isCompleted = false;
};

static std::wstring toWide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w;
    w.resize(len);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

static std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s;
    s.resize(len);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], len, nullptr, nullptr);
    return s;
}

LRESULT CALLBACK PasswordWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    PasswordDialogContext* ctx = reinterpret_cast<PasswordDialogContext*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));

    switch (msg) {
    case WM_CREATE: {
        LPCREATESTRUCTW cs = reinterpret_cast<LPCREATESTRUCTW>(lParam);
        ctx = reinterpret_cast<PasswordDialogContext*>(cs->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(ctx));

        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        
        RECT rcScreen{0,0,GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
        int dlgWidth = rcScreen.right;
        int dlgHeight = rcScreen.bottom;
        int ctrlWidth = 600;
        int editHeight = 32;
        int btnWidth = 140;
        int btnHeight = 36;
        int margin = 24;

        int centerX = dlgWidth / 2;
        int textX = centerX - ctrlWidth / 2;
        int textY = dlgHeight / 2 - 100;
        int editX = textX;
        int editY = textY + 50;
        int btnX = centerX + ctrlWidth / 2 - btnWidth;
        int btnY = editY + editHeight + margin;
        int contactY = editY + editHeight + 8;

        
        HWND hText = CreateWindowExW(0, L"STATIC", ctx->message.c_str(), WS_CHILD | WS_VISIBLE, textX, textY, ctrlWidth, 40, hWnd, nullptr, cs->hInstance, nullptr);
        SendMessageW(hText, WM_SETFONT, (WPARAM)hFont, TRUE);

        
        ctx->editHandle = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL | WS_TABSTOP,
                                          editX, editY, ctrlWidth, editHeight, hWnd, (HMENU)1001, cs->hInstance, nullptr);
        SendMessageW(ctx->editHandle, WM_SETFONT, (WPARAM)hFont, TRUE);

        
        HWND hContact = CreateWindowExW(0, L"STATIC", L"t.me/Radio_Stanok", WS_CHILD | WS_VISIBLE,
                                        editX, contactY, ctrlWidth, 24, hWnd, nullptr, cs->hInstance, nullptr);
        SendMessageW(hContact, WM_SETFONT, (WPARAM)hFont, TRUE);

        
        btnY = contactY + 24 + margin / 2;

        
        ctx->okButtonHandle = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                              btnX, btnY, btnWidth, btnHeight, hWnd, (HMENU)IDOK, cs->hInstance, nullptr);
        SendMessageW(ctx->okButtonHandle, WM_SETFONT, (WPARAM)hFont, TRUE);
        EnableWindow(ctx->okButtonHandle, FALSE);

        
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        SetForegroundWindow(hWnd);

        return 0;
    }
    case WM_COMMAND: {
        const WORD code = HIWORD(wParam);
        const WORD id = LOWORD(wParam);
        const HWND hwndSrc = (HWND)lParam;

        if (hwndSrc == ctx->editHandle && code == EN_CHANGE) {
            int len = GetWindowTextLengthW(ctx->editHandle);
            EnableWindow(ctx->okButtonHandle, len > 0);
            return 0;
        }

        if (id == IDOK && code == BN_CLICKED) {
            int len = GetWindowTextLengthW(ctx->editHandle);
            if (len > 0) {
                std::wstring buffer;
                buffer.resize(len + 1);
                int written = GetWindowTextW(ctx->editHandle, &buffer[0], len + 1);
                if (written < 0) written = 0;
                buffer.resize(static_cast<size_t>(written));

                static const wchar_t kRequiredPasswordW[] = L"c4c2f0b6-2c79-4c1e-9f7b-8a1d7e9a3f21";
                if (buffer == kRequiredPasswordW) {
                    ctx->passwordWide = buffer;
                    ctx->isCompleted = true;
                    DestroyWindow(hWnd);
                } else {
                    MessageBeep(MB_ICONERROR);
                    SetWindowTextW(ctx->editHandle, L"");
                    EnableWindow(ctx->okButtonHandle, FALSE);
                    SetFocus(ctx->editHandle);
                }
            }
            return 0;
        }
        return 0;
    }
    case WM_SYSKEYDOWN: {
        
        if (wParam == VK_F4 || wParam == VK_SPACE) {
            return 0;
        }
        break;
    }
    case WM_SETFOCUS: {
        if (ctx && ctx->editHandle) {
            SetFocus(ctx->editHandle);
        }
        return 0;
    }
    case WM_KILLFOCUS: {
        if (ctx && ctx->editHandle) {
            SetForegroundWindow(hWnd);
            SetFocus(ctx->editHandle);
        }
        return 0;
    }
    case WM_ACTIVATE: {
        if (LOWORD(wParam) == WA_INACTIVE) {
            SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            SetForegroundWindow(hWnd);
            if (ctx && ctx->editHandle) SetFocus(ctx->editHandle);
            return 0;
        }
        break;
    }
    case WM_ACTIVATEAPP: {
        if (wParam == FALSE) {
            SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            SetForegroundWindow(hWnd);
            if (ctx && ctx->editHandle) SetFocus(ctx->editHandle);
            return 0;
        }
        break;
    }
    case WM_SYSCOMMAND: {
        
        UINT cmd = (UINT)(wParam & 0xFFF0);
        if (cmd == SC_MINIMIZE || cmd == SC_CLOSE || cmd == SC_MAXIMIZE || cmd == SC_RESTORE || cmd == SC_MOVE || cmd == SC_SIZE || cmd == SC_KEYMENU) {
            return 0;
        }
        break;
    }
    case WM_NCLBUTTONDBLCLK: {
        return 0;
    }
    case WM_KEYDOWN: {
        if (wParam == VK_ESCAPE) {
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static bool ShowTopmostPasswordDialog(const std::string& titleUtf8, const std::string& messageUtf8, std::string& outPassword) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);

    static const wchar_t kClassName[] = L"FileEnc_PasswordDialog_Class";
    static bool isRegistered = false;
    if (!isRegistered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = PasswordWndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = kClassName;
        isRegistered = (RegisterClassExW(&wc) != 0);
        if (!isRegistered) return false;
    }

    PasswordDialogContext ctx{};
    ctx.title = toWide(titleUtf8);
    ctx.message = toWide(messageUtf8);

    DWORD style = WS_POPUP;
    DWORD exStyle = WS_EX_TOPMOST | WS_EX_DLGMODALFRAME;

    int winW = GetSystemMetrics(SM_CXSCREEN);
    int winH = GetSystemMetrics(SM_CYSCREEN);
    int x = 0;
    int y = 0;

    HWND hWnd = CreateWindowExW(exStyle, kClassName, ctx.title.c_str(), style,
                                x, y, winW, winH, nullptr, nullptr, hInst, &ctx);
    if (!hWnd) return false;

    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);

    
    MSG msg;
    while (!ctx.isCompleted) {
        BOOL gm = GetMessageW(&msg, nullptr, 0, 0);
        if (gm == 0 || gm == -1) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);

        
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    if (ctx.isCompleted) {
        outPassword = toUtf8(ctx.passwordWide);
        return true;
    }
    return false;
}

} 
#endif 

#if defined(__APPLE__) || defined(__linux__)
#include <termios.h>
#include <unistd.h>
#endif

namespace ui {

class MainWindow::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    std::string title_;
    int width_ = 800;
    int height_ = 600;
    int x_ = 0;
    int y_ = 0;
    bool isVisible_ = false;
    std::vector<std::string> files_;
    std::string currentProgressMessage_;
    int currentProgress_ = 0;
};

MainWindow::MainWindow() : pImpl_(std::make_unique<Impl>()) {
    
}

MainWindow::~MainWindow() = default;

void MainWindow::show() {
    pImpl_->isVisible_ = true;
    std::cout << "=== " << pImpl_->title_ << " ===" << std::endl;
    std::cout << "Размер: " << pImpl_->width_ << "x" << pImpl_->height_ << std::endl;
    std::cout << "Позиция: (" << pImpl_->x_ << ", " << pImpl_->y_ << ")" << std::endl;
    std::cout << "Окно показано" << std::endl;
}

void MainWindow::hide() {
    pImpl_->isVisible_ = false;
    std::cout << "Окно скрыто" << std::endl;
}

void MainWindow::setTitle(const std::string& title) {
    pImpl_->title_ = title;
}

void MainWindow::setSize(int width, int height) {
    pImpl_->width_ = width;
    pImpl_->height_ = height;
}

void MainWindow::setPosition(int x, int y) {
    pImpl_->x_ = x;
    pImpl_->y_ = y;
}

void MainWindow::centerOnScreen() {
    
    pImpl_->x_ = 100;
    pImpl_->y_ = 100;
}

void MainWindow::setCloseCallback(std::function<void()> callback) {
    closeCallback_ = callback;
}

void MainWindow::setFileSelectionCallback(std::function<void(const std::vector<std::string>&)> callback) {
    fileSelectionCallback_ = callback;
}

void MainWindow::setEncryptCallback(std::function<void(const std::vector<std::string>&, const std::string&)> callback) {
    encryptCallback_ = callback;
}

void MainWindow::setDecryptCallback(std::function<void(const std::vector<std::string>&, const std::string&)> callback) {
    decryptCallback_ = callback;
}

std::vector<std::string> MainWindow::showFileDialog(const std::string& title, const std::string& filter, bool multiSelect) {
    std::cout << "=== Диалог выбора файлов ===" << std::endl;
    std::cout << "Заголовок: " << title << std::endl;
    std::cout << "Фильтр: " << filter << std::endl;
    std::cout << "Множественный выбор: " << (multiSelect ? "Да" : "Нет") << std::endl;
    
    
    
    std::vector<std::string> testFiles = {
        "C:\\test\\document1.txt",
        "C:\\test\\image1.jpg",
        "C:\\test\\data.xlsx"
    };
    
    std::cout << "Выбрано файлов: " << testFiles.size() << std::endl;
    return testFiles;
}

std::string MainWindow::showPasswordDialog(const std::string& title, const std::string& message) {
    
#ifdef _WIN32
    std::string password;
    bool ok = ShowTopmostPasswordDialog(title, message, password);
    if (ok) {
        return password;
    }
    return std::string();
#else
    std::cout << "=== " << title << " ===" << std::endl;
    std::cout << message << std::endl;

    std::string input;
#if defined(__APPLE__) || defined(__linux__)
    termios oldt{};
    if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
        termios newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        std::getline(std::cin, input);
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl;
    } else {
        std::getline(std::cin, input);
    }
#else
    std::getline(std::cin, input);
#endif
    return input;
#endif
}

void MainWindow::showInfoMessage(const std::string& title, const std::string& message) {
    std::cout << "=== Информационное сообщение ===" << std::endl;
    std::cout << "Заголовок: " << title << std::endl;
    std::cout << "Сообщение: " << message << std::endl;
}

void MainWindow::showErrorMessage(const std::string& title, const std::string& message) {
    std::cout << "=== Сообщение об ошибке ===" << std::endl;
    std::cout << "Заголовок: " << title << std::endl;
    std::cout << "Сообщение: " << message << std::endl;
}

bool MainWindow::showConfirmDialog(const std::string& title, const std::string& message) {
    std::cout << "=== Диалог подтверждения ===" << std::endl;
    std::cout << "Заголовок: " << title << std::endl;
    std::cout << "Сообщение: " << message << std::endl;
    
    
    
    std::cout << "Пользователь подтвердил действие" << std::endl;
    return true;
}

void MainWindow::updateProgress(int value, const std::string& message) {
    pImpl_->currentProgress_ = value;
    pImpl_->currentProgressMessage_ = message;
    
    std::cout << "Прогресс: " << value << "% - " << message << std::endl;
}

void MainWindow::hideProgress() {
    pImpl_->currentProgress_ = 0;
    pImpl_->currentProgressMessage_.clear();
    std::cout << "Индикатор прогресса скрыт" << std::endl;
}

void MainWindow::updateFileList(const std::vector<std::string>& files) {
    pImpl_->files_ = files;
    std::cout << "=== Список файлов обновлен ===" << std::endl;
    for (const auto& file : files) {
        std::cout << "  - " << file << std::endl;
    }
}

void MainWindow::clearFileList() {
    pImpl_->files_.clear();
    std::cout << "Список файлов очищен" << std::endl;
}

} 
