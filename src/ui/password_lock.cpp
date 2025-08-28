#include "password_lock.h"

#include <string>
#include <atomic>
#include <thread>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#elif defined(__linux__)
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#endif

namespace ui {

#ifdef _WIN32
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_CLOSE || (wParam & 0xFFF0) == SC_MINIMIZE || (wParam & 0xFFF0) == SC_MAXIMIZE)
            return 0;
        break;
    case WM_CLOSE:
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
#endif

bool showPasswordLock(const std::string& title, const std::string& message, const std::string& requiredPassword) {
#ifdef _WIN32
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    const wchar_t* cls = L"FileEnc_Lock_Class";
    WNDCLASSW wc{}; wc.lpfnWndProc = WndProc; wc.hInstance = hInst; wc.lpszClassName = cls;
    RegisterClassW(&wc);
    RECT rc{0,0,GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
    HWND hWnd = CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW, cls, L"",
        WS_POPUP, 0, 0, rc.right, rc.bottom, nullptr, nullptr, hInst, nullptr);
    if (!hWnd) return false;
    ShowWindow(hWnd, SW_SHOW);
    UpdateWindow(hWnd);

    // Встроим блок ввода поверх
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD|WS_VISIBLE|ES_PASSWORD|ES_AUTOHSCROLL|WS_TABSTOP,
        rc.right/2 - 300, rc.bottom/2, 400, 32, hWnd, (HMENU)1001, hInst, nullptr);
    SendMessageW(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    HWND hBtn = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
        rc.right/2 + 110, rc.bottom/2, 80, 32, hWnd, (HMENU)IDOK, hInst, nullptr);
    SendMessageW(hBtn, WM_SETFONT, (WPARAM)hFont, TRUE);

    std::wstring req;
    req.resize(requiredPassword.size());
    MultiByteToWideChar(CP_UTF8,0,requiredPassword.c_str(),(int)requiredPassword.size(),&req[0],(int)requiredPassword.size());

    bool success = false;
    MSG msg;
    SetForegroundWindow(hWnd);
    SetFocus(hEdit);
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_COMMAND && LOWORD(msg.wParam) == IDOK) {
            int len = GetWindowTextLengthW(hEdit);
            if (len > 0) {
                std::wstring buf; buf.resize(len+1);
                int w = GetWindowTextW(hEdit, &buf[0], len+1);
                if (w < 0) w = 0; buf.resize((size_t)w);
                if (buf == req) { success = true; break; }
                SetWindowTextW(hEdit, L"");
            }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        SetWindowPos(hWnd, HWND_TOPMOST, 0,0,0,0, SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE);
    }
    DestroyWindow(hWnd);
    return success;
#elif defined(__linux__)
    Display* dpy = XOpenDisplay(nullptr);
    if (!dpy) return false;
    int screen = DefaultScreen(dpy);
    Window root = RootWindow(dpy, screen);
    unsigned int sw = DisplayWidth(dpy, screen);
    unsigned int sh = DisplayHeight(dpy, screen);
    XSetWindowAttributes attr{};
    attr.override_redirect = True; // без декораций и действий WM
    Window win = XCreateWindow(dpy, root, 0, 0, sw, sh, 0, CopyFromParent, InputOutput, CopyFromParent, CWOverrideRedirect, &attr);
    XMapRaised(dpy, win);
    XGrabKeyboard(dpy, win, True, GrabModeAsync, GrabModeAsync, CurrentTime);
    XGrabPointer(dpy, win, True, 0, GrabModeAsync, GrabModeAsync, None, None, CurrentTime);

    // Простая текстовая форма не реализована на Xlib лесно, читаем с stdin без эха
    bool success = false;
    printf("%s\n%s\n", title.c_str(), message.c_str());
    fflush(stdout);
    // скрытый ввод в терминале
    system("stty -echo");
    std::string input; std::getline(std::cin, input);
    system("stty echo");
    if (input == requiredPassword) success = true;

    XUngrabKeyboard(dpy, CurrentTime);
    XUngrabPointer(dpy, CurrentTime);
    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    return success;
#else
    return false;
#endif
}

}


