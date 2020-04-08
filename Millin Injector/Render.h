#pragma once
#include "Common.h"

namespace Render
{
	extern ID3D11Device* g_pd3dDevice;
	extern ID3D11DeviceContext* g_pd3dDeviceContext;
	extern IDXGISwapChain* g_pSwapChain;
	extern ID3D11RenderTargetView* g_mainRenderTargetView;

	extern bool CreateDeviceD3D(HWND hWnd);
	extern void CleanupDeviceD3D();
	extern void CreateRenderTarget();
	extern void CleanupRenderTarget();
	extern LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);