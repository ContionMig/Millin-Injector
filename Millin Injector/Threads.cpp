#include "Common.h"
#include <shellapi.h>

namespace Threads
{
    HANDLE hRenderThread = NULL;
    DWORD RenderThreadID = NULL;
    void RenderThread()
    {
        ErrorLogs::LogFiles("Render Thread Started");

        // Create application window
        WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, Render::WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L"Millin - Injector", NULL };
        ::RegisterClassEx(&wc);
        HWND hwnd = ::CreateWindow(wc.lpszClassName, L"Millin - Injector", WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU, 100, 100, 1280, 800, NULL, NULL, wc.hInstance, NULL);

        // Initialize Direct3D
        if (!Render::CreateDeviceD3D(hwnd))
        {
            Render::CleanupDeviceD3D();
            ::UnregisterClass(wc.lpszClassName, wc.hInstance);
            return;
        }

        // Show the window
        ::ShowWindow(hwnd, SW_SHOWDEFAULT);
        ::UpdateWindow(hwnd);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;

        Menu::ExtasyHostingTheme();

        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(Render::g_pd3dDevice, Render::g_pd3dDeviceContext);

        MSG msg;
        ZeroMemory(&msg, sizeof(msg));

        DragAcceptFiles(hwnd, TRUE);
        while (msg.message != WM_QUIT)
        {
            if (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
            {
                ::TranslateMessage(&msg);
                ::DispatchMessage(&msg);
                continue;
            }

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            Menu::Main();
            if (!ErrorLogs::initialize)
                ErrorLogs::initialize = true;

            ImGui::Render();
            Render::g_pd3dDeviceContext->OMSetRenderTargets(1, &Render::g_mainRenderTargetView, NULL);
            Render::g_pd3dDeviceContext->ClearRenderTargetView(Render::g_mainRenderTargetView, (float*)&ImVec4(0.45f, 0.55f, 0.60f, 1.00f));
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            Render::g_pSwapChain->Present(1, 0);
        }

        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        Render::CleanupDeviceD3D();
        ::DestroyWindow(hwnd);
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    }

}