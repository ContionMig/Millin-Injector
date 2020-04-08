#include "Common.h"
#include "imgui_internal.h"
#include "imguistyleserializer.h"

#define HI(v)   ImVec4(0.502f, 0.075f, 0.256f, v)
#define MED(v)  ImVec4(0.455f, 0.198f, 0.301f, v)
#define LOW(v)  ImVec4(0.232f, 0.201f, 0.271f, v)
#define BG(v)   ImVec4(0.200f, 0.220f, 0.270f, v)
#define TEXT(v) ImVec4(0.860f, 0.930f, 0.890f, v)

namespace Menu
{
    sConsole MainConsole;
    char DLLPath[MAX_PATH] = "D:\\Sources\\Millin Injector\\x64\\Release\\SampleDLL.dll";

	void Main()
	{
        static int PrcessSelected = -1;
        static int ModuleSelected = 0;

        ImGuiWindowFlags window_flags = 0;
        window_flags |= ImGuiWindowFlags_NoCollapse;
        window_flags |= ImGuiWindowFlags_NoMove;
        window_flags |= ImGuiWindowFlags_NoResize;
        window_flags |= ImGuiCol_PopupBg;

        ImGui::SetNextWindowPos(ImVec2(-1,0));
        ImGui::SetNextWindowSize(ImVec2(1267, 622));

        if (ImGui::Begin("Main", NULL, window_flags))
        {
            if (ImGui::BeginTabBar("##MainTabs"))
            {
                if (ImGui::BeginTabItem("Processes"))
                {
                    ImGui::Text("Processes");
                    if (ImGui::BeginChild("##Processes", ImVec2(1250, 540), true))
                    {
                        ImGui::Columns(5, "ProcessColumns", false);

                        ImGui::SetColumnWidth(0, 60);
                        ImGui::SetColumnWidth(1, 250);
                        ImGui::SetColumnWidth(2, 250);
                        ImGui::SetColumnWidth(3, 60);

                        ImGui::Separator();
                        ImGui::Text("PID"); ImGui::NextColumn();
                        ImGui::Text("Name"); ImGui::NextColumn();
                        ImGui::Text("Window Name"); ImGui::NextColumn();
                        ImGui::Text("RAM"); ImGui::NextColumn();
                        ImGui::Text("Full Path"); ImGui::NextColumn();
                        ImGui::Separator();

                        for (int i = 0; i < Process::ProcessList.GetSize(); i++)
                        {
                            char label[32];
                            sprintf(label, "%d", Process::ProcessList.PID[i]);
                            if (ImGui::Selectable(label, PrcessSelected == i, ImGuiSelectableFlags_SpanAllColumns))
                                PrcessSelected = i;
                            bool hovered = ImGui::IsItemHovered();
                            ImGui::NextColumn();
                            ImGui::Text(Process::ProcessList.Name[i].c_str()); ImGui::NextColumn();
                            ImGui::Text(Process::ProcessList.WindowName[i].c_str()); ImGui::NextColumn();
                            ImGui::Text("%d MB", Process::ProcessList.Ram[i]); ImGui::NextColumn();
                            ImGui::Text(Process::ProcessList.FullPath[i].c_str()); ImGui::NextColumn();
                        }
                        ImGui::Columns(1);
                        ImGui::Separator();
                        ImGui::TreePop();

                        ImGui::EndChild();
                    }
                   
                    static bool ShowAllModules = false;
                    if (PrcessSelected > -1)
                    {
                        if (ImGui::Button("Select"))
                        {
                            if (!Helpers::CheckAlive(Process::ProcessList.PID[PrcessSelected]))
                            {
                                CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Process::RefreshProcessList, NULL, NULL, NULL);
                                PrcessSelected = -1;
                            }
                            else
                            {
                                Process::SelectedProcess.PID = Process::ProcessList.PID[PrcessSelected];
                                Process::SelectedProcess.Name = Process::ProcessList.Name[PrcessSelected];
                                Process::SelectedProcess.WindowName = Process::ProcessList.WindowName[PrcessSelected];
                                Process::SelectedProcess.FullPath = Process::ProcessList.FullPath[PrcessSelected];
                                Process::SelectedProcess.TotalThreads = Process::ProcessList.Threads[PrcessSelected];
                                CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Process::RefreshSelect, &ShowAllModules, NULL, NULL);
                            }
                        }
                        ImGui::SameLine();

                        if (ImGui::Button("Terminate"))
                        {
                            if (!TerminateProcess(OpenProcess(PROCESS_TERMINATE, NULL, Process::ProcessList.PID[PrcessSelected]), 0))
                                ErrorLogs::LogFiles("TerminateProcess Failed");
                        }
                        ImGui::SameLine();
                    }

                    if (ImGui::Button("Refresh"))
                    {
                        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Process::RefreshProcessList, NULL, NULL, NULL);
                        PrcessSelected = -1;
                    } ImGui::SameLine();

                    ImGui::Checkbox("Hidden Modules", &ShowAllModules); 
                    ImGui::EndTabItem();
                }
                
                if (ImGui::BeginTabItem("Modules"))
                {
                    ImGui::Text("Modules");
                    if (ImGui::BeginChild("##Modules", ImVec2(1250, 540), true))
                    {
                        ImGui::Columns(5, "ModulesColumns", false);
                        ImGui::SetColumnWidth(0, 60);
                        ImGui::SetColumnWidth(1, 200);
                        ImGui::SetColumnWidth(2, 150);
                        ImGui::SetColumnWidth(3, 150);

                        ImGui::Separator();
                        ImGui::Text("ID"); ImGui::NextColumn();
                        ImGui::Text("Name"); ImGui::NextColumn();
                        ImGui::Text("Base Address"); ImGui::NextColumn();
                        ImGui::Text("BaseSize"); ImGui::NextColumn();
                        ImGui::Text("Full Path"); ImGui::NextColumn();
                        ImGui::Separator();

                        for (int i = 0; i < Process::SelectedProcess.Modules.size(); i++)
                        {
                            char label[32];
                            sprintf(label, "%d", i);
                            if (ImGui::Selectable(label, ModuleSelected == i, ImGuiSelectableFlags_SpanAllColumns))
                                ModuleSelected = i;
                            bool hovered = ImGui::IsItemHovered();
                            ImGui::NextColumn();
                            ImGui::Text(Process::SelectedProcess.Modules[i].Name.c_str()); ImGui::NextColumn();
                            ImGui::Text("0x%llx", Process::SelectedProcess.Modules[i].BaseAddress); ImGui::NextColumn();
                            ImGui::Text("0x%llx", Process::SelectedProcess.Modules[i].BaseSize); ImGui::NextColumn();
                            ImGui::Text(Process::SelectedProcess.Modules[i].FullPath.c_str()); ImGui::NextColumn();
                        }
                        ImGui::Columns(1);
                        ImGui::Separator();
                        ImGui::TreePop();

                        ImGui::EndChild();
                    }

                    if (ModuleSelected > -1)
                    {
                        if (ImGui::Button("Select"))
                        {
                            Process::Imports.FullPath = Process::SelectedProcess.Modules[ModuleSelected].FullPath;
                            CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Process::RefeshSelectImport, NULL, NULL, NULL);
                        }
                        ImGui::SameLine();
                    }

                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Imports"))
                {
                    if (Process::SelectedProcess.Modules.size() > ModuleSelected)
                        ImGui::Text("Imports Of: %s", Process::SelectedProcess.Modules[ModuleSelected].Name.c_str());
                    else
                        ImGui::Text("Imports");

                    if (ImGui::BeginChild("##Imports", ImVec2(1250, 550), true))
                    {
                        // Using ImGui::Text On Loop, as i was testing some stuff and TextWarapped or Text itself didnt do the trick.
                        // So i am just going to use a vector instead
                        for (int i = 0; i < Process::Imports.importDescriptor.size(); i++)
                            ImGui::Text(Process::Imports.importDescriptor[i].c_str());

                        ImGui::EndChild();
                    }
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Injection"))
                {
                    ImGui::Dummy(ImVec2(0, 10));

                    ImGui::Text("Injections:");
                    if (ImGui::BeginChild("##Create Thread", ImVec2(1237 / 3, 600 / 2), true))
                    {
                        static bool ManualMap = false;
                        static InjectionOptions Options;
                        Options.OptionChoice = 0;
                        Options.sFilePath = DLLPath;

                        ImGui::Text("Create Threads");
                        const char* CreateThreadItems[] = { "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread" };
                        ImGui::Combo("##CreateThreadItems", &Options.ComboVariable, CreateThreadItems, IM_ARRAYSIZE(CreateThreadItems));
                        ImGui::DragInt("Delay (S)", &Options.DelayS, 0.2f, 0, 10);
                        ImGui::Checkbox("Use Full Handle Permissions", &Options.FullPermsHandle);
                        ImGui::Checkbox("Manual Map", &ManualMap);
                        ImGui::Checkbox("Change Start Address", &Options.CheckBoxVarible2);
                        ImGui::Checkbox("Hide Thread From Debugger", &Options.CheckBoxVarible3);
                        ImGui::Checkbox("Clear PE Headers", &Options.CheckBoxVarible4);
                        ImGui::Text("");
                        ImGui::Checkbox("Unlink From Load Order List", &Options.CheckBoxVarible5);
                        ImGui::Checkbox("Unlink From Memory Order List", &Options.CheckBoxVarible6);
                        ImGui::Checkbox("Unlink From Initialization Order List", &Options.CheckBoxVarible7);

                        if (ImGui::Button("INJECT", ImVec2(1250 / 4 - 5, 40)))
                        {
                            if (!ManualMap)
                                CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Injection::LoadLibraryInject, &Options, 0, NULL);
                            else
                                CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Injection::ManualMapInject, &Options, 0, NULL);
                        }

                        ImGui::EndChild();
                    }
                    ImGui::SameLine();
                    if (ImGui::BeginChild("##APCinjection", ImVec2(1237 / 3, 600 / 2), true))
                    {
                        static InjectionOptions Options;
                        Options.OptionChoice = 1;
                        Options.sFilePath = DLLPath;

                        ImGui::Text("APCinjection");

                        ImGui::DragInt("Delay (S)", &Options.DelayS, 0.2f, 0, 10);
                        ImGui::Checkbox("Use Full Handle Permissions", &Options.FullPermsHandle);
                        ImGui::Checkbox("Clear PE Headers", &Options.CheckBoxVarible4);
                        ImGui::Text("");
                        ImGui::Checkbox("Unlink From Load Order List", &Options.CheckBoxVarible5);
                        ImGui::Checkbox("Unlink From Memory Order List", &Options.CheckBoxVarible6);
                        ImGui::Checkbox("Unlink From Initialization Order List", &Options.CheckBoxVarible7);

                        if (ImGui::Button("INJECT", ImVec2(1250 / 4 - 5, 40)))
                            CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Injection::LoadLibraryInject, &Options, 0, NULL);

                        ImGui::EndChild();
                    }
                    ImGui::SameLine();
                    if (ImGui::BeginChild("##SetWindowsHookEx", ImVec2(1237 / 3, 600 / 2 ), true))
                    {
                        static InjectionOptions Options;
                        Options.OptionChoice = 2;
                        Options.sFilePath = DLLPath;

                        ImGui::Text("SetWindowsHookEx");

                        const char* HookItems[] = { "WH_CBT (Caution)", "WH_GETMESSAGE (Auto)", "WH_KEYBOARD (Manual)"};
                        ImGui::Combo("##HookItems", &Options.ComboVariable, HookItems, IM_ARRAYSIZE(HookItems));
                        if (Options.ComboVariable == 0 || Options.ComboVariable == 2)
                            ImGui::DragInt("Hook Duration (MS)", &Options.DurationMS, 0.2f, 0, 5000);

                        ImGui::DragInt("Delay (S)", &Options.DelayS, 0.2f, 0, 10);
                        ImGui::Checkbox("Use Full Handle Permissions", &Options.FullPermsHandle);
                        ImGui::Checkbox("Use Entry Point", &Options.CheckBoxVarible);
                        if (!Options.CheckBoxVarible)
                            ImGui::InputText("Custom Function", Options.CustomEntryPoint, IM_ARRAYSIZE(Options.CustomEntryPoint));
                        ImGui::Checkbox("Clear PE Headers", &Options.CheckBoxVarible4);
                        ImGui::Text("");
                        ImGui::Checkbox("Unlink From Load Order List", &Options.CheckBoxVarible5);
                        ImGui::Checkbox("Unlink From Memory Order List", &Options.CheckBoxVarible6);
                        ImGui::Checkbox("Unlink From Initialization Order List", &Options.CheckBoxVarible7);

                        if (ImGui::Button("INJECT", ImVec2(1250 / 4 - 5, 40)))
                            CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Injection::LoadLibraryInject, &Options, 0, NULL);

                        ImGui::EndChild();
                    }

                    if (ImGui::BeginChild("##Theme", ImVec2(1250, 600 / 2 - 90), true))
                    {
                        static int style_idx = 4;
                        ImGui::SetNextItemWidth(1187);
                        if (ImGui::Combo("Theme", &style_idx, "ImGui Classic\0ImGui Dark\0ImGui Light\0Cherry Theme\0Extasy's Theme"))
                        {
                            switch (style_idx)
                            {
                            case 0: ImGui::StyleColorsClassic(); break;
                            case 1: ImGui::StyleColorsDark(); break;
                            case 2: ImGui::StyleColorsLight(); break;
                            case 3: CherryTheme(); break;
                            case 4: ExtasyHostingTheme(); break;
                            }
                        }

                        ShowStyleEditor();

                        ImGui::EndChild();
                    }

                    ImGui::Dummy(ImVec2(0, 5));
                    ImGui::SetNextItemWidth(1187);
                    ImGui::InputText("DLL Path", DLLPath, IM_ARRAYSIZE(DLLPath));

                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Console"))
                {
                    MainConsole.Draw("Main Console", NULL);
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::End();
        }
       

        ImGui::SetNextWindowPos(ImVec2(-1, 621));
        ImGui::SetNextWindowSize(ImVec2(1266, 141));

        if (ImGui::Begin("Info", NULL, window_flags))
        {
            if (ImGui::BeginChild("##Main Info", ImVec2(1250, 115), true))
            {
                if (Process::SelectedProcess.Initialize)
                {
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f),"Process:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), Process::SelectedProcess.Name.c_str()); ImGui::SameLine();
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Process ID:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), "%d", Process::SelectedProcess.PID);  ImGui::SameLine();
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Type:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), Process::SelectedProcess.Is64 ? "64 Bit" : "32 Bit");

                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Full Path:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), Process::SelectedProcess.FullPath.c_str()); 
                
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Base Address:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), "0x%llx", Process::SelectedProcess.BaseAddress);  ImGui::SameLine();
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Base Size:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), "0x%llx", Process::SelectedProcess.BaseSize);  ImGui::SameLine();
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Total Modules:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), "%d", Process::SelectedProcess.TotalModules);  ImGui::SameLine();
                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Total Threads:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), "%d", Process::SelectedProcess.TotalThreads);

                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Common Rendering Module:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), "%s", Process::SelectedProcess.RenderingModule.c_str());

                    ImGui::TextColored(ImColor(0.2f, 1.f, 0.2f), "Elevated:"); ImGui::SameLine(); ImGui::TextColored(ImColor(1.f, 1.f, 1.f), Process::SelectedProcess.Elevated ? "TRUE" : "FALSE");
                }
                ImGui::EndChild();
            }
            ImGui::End();
        }
	}
   
    void ShowStyleEditor(ImGuiStyle* ref)
    {
        // You can pass in a reference ImGuiStyle structure to compare to, revert to and save to (else it compares to an internally stored reference)
        ImGuiStyle& style = ImGui::GetStyle();
        static ImGuiStyle ref_saved_style;

        // Default to using internal storage as reference
        static bool init = true;
        if (init && ref == NULL)
            ref_saved_style = style;
        init = false;
        if (ref == NULL)
            ref = &ref_saved_style;

        ImGui::PushItemWidth(ImGui::GetWindowWidth() * 0.50f);
        ImGui::ShowFontSelector("Fonts##Selector");

        // Simplified Settings
        { bool window_border = (style.WindowBorderSize > 0.0f); if (ImGui::Checkbox("WindowBorder", &window_border)) style.WindowBorderSize = window_border ? 1.0f : 0.0f; }
        ImGui::SameLine();
        { bool frame_border = (style.FrameBorderSize > 0.0f); if (ImGui::Checkbox("FrameBorder", &frame_border)) style.FrameBorderSize = frame_border ? 1.0f : 0.0f; }
        ImGui::SameLine();
        { bool popup_border = (style.PopupBorderSize > 0.0f); if (ImGui::Checkbox("PopupBorder", &popup_border)) style.PopupBorderSize = popup_border ? 1.0f : 0.0f; }

        // Save/Revert button
        if (ImGui::Button("Save Theme"))
            ImGui::ImGuiSaveStyle("imguistyle.ini", style);
        ImGui::SameLine();
        if (ImGui::Button("Load Theme"))
            ImGui::ImGuiLoadStyle("imguistyle.ini", style);
        ImGui::SameLine();

        ImGui::Separator();

        if (ImGui::BeginTabBar("##tabs", ImGuiTabBarFlags_None))
        {
            if (ImGui::BeginTabItem("Sizes"))
            {
                ImGui::Text("Main");
                ImGui::SliderFloat2("WindowPadding", (float*)&style.WindowPadding, 0.0f, 20.0f, "%.0f");
                ImGui::SliderFloat2("FramePadding", (float*)&style.FramePadding, 0.0f, 20.0f, "%.0f");
                ImGui::SliderFloat2("ItemSpacing", (float*)&style.ItemSpacing, 0.0f, 20.0f, "%.0f");
                ImGui::SliderFloat2("ItemInnerSpacing", (float*)&style.ItemInnerSpacing, 0.0f, 20.0f, "%.0f");
                ImGui::SliderFloat2("TouchExtraPadding", (float*)&style.TouchExtraPadding, 0.0f, 10.0f, "%.0f");
                ImGui::SliderFloat("IndentSpacing", &style.IndentSpacing, 0.0f, 30.0f, "%.0f");
                ImGui::SliderFloat("ScrollbarSize", &style.ScrollbarSize, 1.0f, 20.0f, "%.0f");
                ImGui::SliderFloat("GrabMinSize", &style.GrabMinSize, 1.0f, 20.0f, "%.0f");
                ImGui::Text("Borders");
                ImGui::SliderFloat("WindowBorderSize", &style.WindowBorderSize, 0.0f, 1.0f, "%.0f");
                ImGui::SliderFloat("ChildBorderSize", &style.ChildBorderSize, 0.0f, 1.0f, "%.0f");
                ImGui::SliderFloat("PopupBorderSize", &style.PopupBorderSize, 0.0f, 1.0f, "%.0f");
                ImGui::SliderFloat("FrameBorderSize", &style.FrameBorderSize, 0.0f, 1.0f, "%.0f");
                ImGui::SliderFloat("TabBorderSize", &style.TabBorderSize, 0.0f, 1.0f, "%.0f");
                ImGui::Text("Rounding");
                ImGui::SliderFloat("WindowRounding", &style.WindowRounding, 0.0f, 12.0f, "%.0f");
                ImGui::SliderFloat("ChildRounding", &style.ChildRounding, 0.0f, 12.0f, "%.0f");
                ImGui::SliderFloat("FrameRounding", &style.FrameRounding, 0.0f, 12.0f, "%.0f");
                ImGui::SliderFloat("PopupRounding", &style.PopupRounding, 0.0f, 12.0f, "%.0f");
                ImGui::SliderFloat("ScrollbarRounding", &style.ScrollbarRounding, 0.0f, 12.0f, "%.0f");
                ImGui::SliderFloat("GrabRounding", &style.GrabRounding, 0.0f, 12.0f, "%.0f");
                ImGui::SliderFloat("TabRounding", &style.TabRounding, 0.0f, 12.0f, "%.0f");
                ImGui::Text("Alignment");
                ImGui::SliderFloat2("WindowTitleAlign", (float*)&style.WindowTitleAlign, 0.0f, 1.0f, "%.2f");
                int window_menu_button_position = style.WindowMenuButtonPosition + 1;
                if (ImGui::Combo("WindowMenuButtonPosition", (int*)&window_menu_button_position, "None\0Left\0Right\0"))
                    style.WindowMenuButtonPosition = window_menu_button_position - 1;
                ImGui::Combo("ColorButtonPosition", (int*)&style.ColorButtonPosition, "Left\0Right\0");
                ImGui::SliderFloat2("ButtonTextAlign", (float*)&style.ButtonTextAlign, 0.0f, 1.0f, "%.2f"); ImGui::SameLine(); 
                ImGui::SliderFloat2("SelectableTextAlign", (float*)&style.SelectableTextAlign, 0.0f, 1.0f, "%.2f"); ImGui::SameLine();
                ImGui::Text("Safe Area Padding"); ImGui::SameLine();
                ImGui::SliderFloat2("DisplaySafeAreaPadding", (float*)&style.DisplaySafeAreaPadding, 0.0f, 30.0f, "%.0f");
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Colors"))
            {
                static int output_dest = 0;
                static bool output_only_modified = true;

                static ImGuiTextFilter filter;
                filter.Draw("Filter colors", ImGui::GetFontSize() * 16);

                static ImGuiColorEditFlags alpha_flags = 0;
                if (ImGui::RadioButton("Opaque", alpha_flags == 0)) { alpha_flags = 0; } ImGui::SameLine();
                if (ImGui::RadioButton("Alpha", alpha_flags == ImGuiColorEditFlags_AlphaPreview)) { alpha_flags = ImGuiColorEditFlags_AlphaPreview; } ImGui::SameLine();
                if (ImGui::RadioButton("Both", alpha_flags == ImGuiColorEditFlags_AlphaPreviewHalf)) { alpha_flags = ImGuiColorEditFlags_AlphaPreviewHalf; } ImGui::SameLine();

                ImGui::BeginChild("##colors", ImVec2(0, 0), true, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_AlwaysHorizontalScrollbar | ImGuiWindowFlags_NavFlattened);
                ImGui::PushItemWidth(-160);
                for (int i = 0; i < ImGuiCol_COUNT; i++)
                {
                    const char* name = ImGui::GetStyleColorName(i);
                    if (!filter.PassFilter(name))
                        continue;
                    ImGui::PushID(i);
                    ImGui::ColorEdit4("##color", (float*)&style.Colors[i], ImGuiColorEditFlags_AlphaBar | alpha_flags);
                    if (memcmp(&style.Colors[i], &ref->Colors[i], sizeof(ImVec4)) != 0)
                    {
                        // Tips: in a real user application, you may want to merge and use an icon font into the main font, so instead of "Save"/"Revert" you'd use icons.
                        // Read the FAQ and docs/FONTS.txt about using icon fonts. It's really easy and super convenient!
                        ImGui::SameLine(0.0f, style.ItemInnerSpacing.x); if (ImGui::Button("Save")) ref->Colors[i] = style.Colors[i];
                        ImGui::SameLine(0.0f, style.ItemInnerSpacing.x); if (ImGui::Button("Revert")) style.Colors[i] = ref->Colors[i];
                    }
                    ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
                    ImGui::TextUnformatted(name);
                    ImGui::PopID();
                }
                ImGui::PopItemWidth();
                ImGui::EndChild();

                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Fonts"))
            {
                ImGuiIO& io = ImGui::GetIO();
                ImFontAtlas* atlas = io.Fonts;

                ImGui::PushItemWidth(120);
                for (int i = 0; i < atlas->Fonts.Size; i++)
                {
                    ImFont* font = atlas->Fonts[i];
                    ImGui::PushID(font);
                    bool font_details_opened = ImGui::TreeNode(font, "Font %d: \"%s\"\n%.2f px, %d glyphs, %d file(s)", i, font->ConfigData ? font->ConfigData[0].Name : "", font->FontSize, font->Glyphs.Size, font->ConfigDataCount);
                    ImGui::SameLine(); if (ImGui::SmallButton("Set as default")) { io.FontDefault = font; }
                    if (font_details_opened)
                    {
                        ImGui::PushFont(font);
                        ImGui::Text("The quick brown fox jumps over the lazy dog");
                        ImGui::PopFont();
                        ImGui::DragFloat("Font scale", &font->Scale, 0.005f, 0.3f, 2.0f, "%.1f");   // Scale only this font
                        ImGui::SameLine(); 
                        ImGui::InputFloat("Font offset", &font->DisplayOffset.y, 1, 1, "%.0f");
                        ImGui::Text("Ascent: %f, Descent: %f, Height: %f", font->Ascent, font->Descent, font->Ascent - font->Descent);
                        ImGui::Text("Fallback character: '%c' (U+%04X)", font->FallbackChar, font->FallbackChar);
                        ImGui::Text("Ellipsis character: '%c' (U+%04X)", font->EllipsisChar, font->EllipsisChar);
                        const float surface_sqrt = sqrtf((float)font->MetricsTotalSurface);
                        ImGui::Text("Texture Area: about %d px ~%dx%d px", font->MetricsTotalSurface, (int)surface_sqrt, (int)surface_sqrt);
                        for (int config_i = 0; config_i < font->ConfigDataCount; config_i++)
                            if (font->ConfigData)
                                if (const ImFontConfig* cfg = &font->ConfigData[config_i])
                                    ImGui::BulletText("Input %d: \'%s\', Oversample: (%d,%d), PixelSnapH: %d", config_i, cfg->Name, cfg->OversampleH, cfg->OversampleV, cfg->PixelSnapH);
                        if (ImGui::TreeNode("Glyphs", "Glyphs (%d)", font->Glyphs.Size))
                        {
                            // Display all glyphs of the fonts in separate pages of 256 characters
                            for (unsigned int base = 0; base <= IM_UNICODE_CODEPOINT_MAX; base += 256)
                            {
                                // Skip ahead if a large bunch of glyphs are not present in the font (test in chunks of 4k)
                                // This is only a small optimization to reduce the number of iterations when IM_UNICODE_MAX_CODEPOINT is large.
                                // (if ImWchar==ImWchar32 we will do at least about 272 queries here)
                                if (!(base & 4095) && font->IsGlyphRangeUnused(base, base + 4095))
                                {
                                    base += 4096 - 256;
                                    continue;
                                }

                                int count = 0;
                                for (unsigned int n = 0; n < 256; n++)
                                    count += font->FindGlyphNoFallback((ImWchar)(base + n)) ? 1 : 0;
                                if (count > 0 && ImGui::TreeNode((void*)(intptr_t)base, "U+%04X..U+%04X (%d %s)", base, base + 255, count, count > 1 ? "glyphs" : "glyph"))
                                {
                                    float cell_size = font->FontSize * 1;
                                    float cell_spacing = style.ItemSpacing.y;
                                    ImVec2 base_pos = ImGui::GetCursorScreenPos();
                                    ImDrawList* draw_list = ImGui::GetWindowDrawList();
                                    for (unsigned int n = 0; n < 256; n++)
                                    {
                                        ImVec2 cell_p1(base_pos.x + (n % 16) * (cell_size + cell_spacing), base_pos.y + (n / 16) * (cell_size + cell_spacing));
                                        ImVec2 cell_p2(cell_p1.x + cell_size, cell_p1.y + cell_size);
                                        const ImFontGlyph* glyph = font->FindGlyphNoFallback((ImWchar)(base + n));
                                        draw_list->AddRect(cell_p1, cell_p2, glyph ? IM_COL32(255, 255, 255, 100) : IM_COL32(255, 255, 255, 50));
                                        if (glyph)
                                            font->RenderChar(draw_list, cell_size, cell_p1, ImGui::GetColorU32(ImGuiCol_Text), (ImWchar)(base + n)); // We use ImFont::RenderChar as a shortcut because we don't have UTF-8 conversion functions available to generate a string.
                                        if (glyph && ImGui::IsMouseHoveringRect(cell_p1, cell_p2))
                                        {
                                            ImGui::BeginTooltip();
                                            ImGui::Text("Codepoint: U+%04X", base + n);
                                            ImGui::Separator();
                                            ImGui::Text("Visible: %d", glyph->Visible);
                                            ImGui::Text("AdvanceX: %.1f", glyph->AdvanceX);
                                            ImGui::Text("Pos: (%.2f,%.2f)->(%.2f,%.2f)", glyph->X0, glyph->Y0, glyph->X1, glyph->Y1);
                                            ImGui::Text("UV: (%.3f,%.3f)->(%.3f,%.3f)", glyph->U0, glyph->V0, glyph->U1, glyph->V1);
                                            ImGui::EndTooltip();
                                        }
                                    }
                                    ImGui::Dummy(ImVec2((cell_size + cell_spacing) * 16, (cell_size + cell_spacing) * 16));
                                    ImGui::TreePop();
                                }
                            }
                            ImGui::TreePop();
                        }
                        ImGui::TreePop();
                    }
                    ImGui::PopID();
                }
                if (ImGui::TreeNode("Atlas texture", "Atlas texture (%dx%d pixels)", atlas->TexWidth, atlas->TexHeight))
                {
                    ImVec4 tint_col = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
                    ImVec4 border_col = ImVec4(1.0f, 1.0f, 1.0f, 0.5f);
                    ImGui::Image(atlas->TexID, ImVec2((float)atlas->TexWidth, (float)atlas->TexHeight), ImVec2(0, 0), ImVec2(1, 1), tint_col, border_col);
                    ImGui::TreePop();
                }

               
                static float window_scale = 1.0f;
                if (ImGui::DragFloat("window scale", &window_scale, 0.005f, 0.3f, 2.0f, "%.2f"))   // scale only this window
                    ImGui::SetWindowFontScale(window_scale);
                ImGui::DragFloat("global scale", &io.FontGlobalScale, 0.005f, 0.3f, 2.0f, "%.2f");      // scale everything
                ImGui::PopItemWidth();

                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Rendering"))
            {
                ImGui::Checkbox("Anti-aliased lines", &style.AntiAliasedLines); ImGui::SameLine(); 
                ImGui::Checkbox("Anti-aliased fill", &style.AntiAliasedFill);
                ImGui::PushItemWidth(100);
                ImGui::DragFloat("Curve Tessellation Tolerance", &style.CurveTessellationTol, 0.02f, 0.10f, 10.0f, "%.2f");
                if (style.CurveTessellationTol < 0.10f) style.CurveTessellationTol = 0.10f;
                ImGui::DragFloat("Circle segment Max Error", &style.CircleSegmentMaxError, 0.01f, 0.10f, 10.0f, "%.2f");
                ImGui::DragFloat("Global Alpha", &style.Alpha, 0.005f, 0.20f, 1.0f, "%.2f"); // Not exposing zero here so user doesn't "lose" the UI (zero alpha clips all widgets). But application code could have a toggle to switch between zero and non-zero.
                ImGui::PopItemWidth();

                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::PopItemWidth();
    }

    void CherryTheme() 
    {
        // https://github.com/ocornut/imgui/issues/707#issuecomment-430613104
        auto& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_Text] = TEXT(0.78f);
        style.Colors[ImGuiCol_TextDisabled] = TEXT(0.28f);
        style.Colors[ImGuiCol_WindowBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.00f);
        style.Colors[ImGuiCol_PopupBg] = BG(0.9f);
        style.Colors[ImGuiCol_Border] = ImVec4(0.31f, 0.31f, 1.00f, 0.00f);
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        style.Colors[ImGuiCol_FrameBg] = BG(1.00f);
        style.Colors[ImGuiCol_FrameBgHovered] = MED(0.78f);
        style.Colors[ImGuiCol_FrameBgActive] = MED(1.00f);
        style.Colors[ImGuiCol_TitleBg] = LOW(1.00f);
        style.Colors[ImGuiCol_TitleBgActive] = HI(1.00f);
        style.Colors[ImGuiCol_TitleBgCollapsed] = BG(0.75f);
        style.Colors[ImGuiCol_MenuBarBg] = BG(0.47f);
        style.Colors[ImGuiCol_ScrollbarBg] = BG(1.00f);
        style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.09f, 0.15f, 0.16f, 1.00f);
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = MED(0.78f);
        style.Colors[ImGuiCol_ScrollbarGrabActive] = MED(1.00f);
        style.Colors[ImGuiCol_CheckMark] = ImVec4(0.71f, 0.22f, 0.27f, 1.00f);
        style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.47f, 0.77f, 0.83f, 0.14f);
        style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.71f, 0.22f, 0.27f, 1.00f);
        style.Colors[ImGuiCol_Button] = ImVec4(0.47f, 0.77f, 0.83f, 0.14f);
        style.Colors[ImGuiCol_ButtonHovered] = MED(0.86f);
        style.Colors[ImGuiCol_ButtonActive] = MED(1.00f);
        style.Colors[ImGuiCol_Header] = MED(0.76f);
        style.Colors[ImGuiCol_HeaderHovered] = MED(0.86f);
        style.Colors[ImGuiCol_HeaderActive] = HI(1.00f);
        style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.47f, 0.77f, 0.83f, 0.04f);
        style.Colors[ImGuiCol_ResizeGripHovered] = MED(0.78f);
        style.Colors[ImGuiCol_ResizeGripActive] = MED(1.00f);
        style.Colors[ImGuiCol_PlotLines] = TEXT(0.63f);
        style.Colors[ImGuiCol_PlotLinesHovered] = MED(1.00f);
        style.Colors[ImGuiCol_PlotHistogram] = TEXT(0.63f);
        style.Colors[ImGuiCol_PlotHistogramHovered] = MED(1.00f);
        style.Colors[ImGuiCol_TextSelectedBg] = MED(0.43f);
        style.Colors[ImGuiCol_ModalWindowDarkening] = BG(0.73f);

        style.WindowPadding = ImVec2(6, 4);
        style.WindowRounding = 0.0f;
        style.FramePadding = ImVec2(5, 2);
        style.FrameRounding = 8.f;
        style.ItemSpacing = ImVec2(7, 3);
        style.ItemInnerSpacing = ImVec2(1, 1);
        style.TouchExtraPadding = ImVec2(0, 0);
        style.IndentSpacing = 6.0f;
        style.ScrollbarSize = 12.0f;
        style.ScrollbarRounding = 16.0f;
        style.GrabMinSize = 20.0f;
        style.GrabRounding = 8.f;
        style.ChildRounding = 8.f;

        style.WindowTitleAlign.x = 0.50f;

        style.Colors[ImGuiCol_Border] = ImVec4(0.539f, 0.479f, 0.255f, 0.162f);
        style.FrameBorderSize = 0.0f;
        style.WindowBorderSize = 1.0f;
    }

    void ExtasyHostingTheme()
    {
        ImGuiStyle* style = &ImGui::GetStyle();

        style->WindowPadding = ImVec2(6, 4);
        style->WindowRounding = 0.0f;
        style->FramePadding = ImVec2(5, 2);
        style->FrameRounding = 8.f;
        style->ItemSpacing = ImVec2(7, 3);
        style->ItemInnerSpacing = ImVec2(1, 1);
        style->TouchExtraPadding = ImVec2(0, 0);
        style->IndentSpacing = 6.0f;
        style->ScrollbarSize = 12.0f;
        style->ScrollbarRounding = 16.0f;
        style->GrabMinSize = 20.0f;
        style->GrabRounding = 8.f;
        style->ChildRounding = 8.f;
        style->WindowTitleAlign.x = 0.50f;
        style->FrameBorderSize = 0.0f;
        style->WindowBorderSize = 1.0f;

        style->Colors[ImGuiCol_Text] = ImVec4(0.80f, 0.80f, 0.83f, 1.00f);
        style->Colors[ImGuiCol_TextDisabled] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
        style->Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
        style->Colors[ImGuiCol_PopupBg] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
        style->Colors[ImGuiCol_Border] = ImVec4(0.80f, 0.80f, 0.83f, 0.88f);
        style->Colors[ImGuiCol_BorderShadow] = ImVec4(0.92f, 0.91f, 0.88f, 0.00f);
        style->Colors[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
        style->Colors[ImGuiCol_FrameBgActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
        style->Colors[ImGuiCol_Tab] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_TabActive] = ImVec4(0.20f, 0.09f, 0.22f, 1.00f);
        style->Colors[ImGuiCol_TabHovered] = ImVec4(0.15f, 0.09f, 0.17f, 1.00f);
        style->Colors[ImGuiCol_Tab] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(1.00f, 0.98f, 0.95f, 0.75f);
        style->Colors[ImGuiCol_TitleBgActive] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
        style->Colors[ImGuiCol_MenuBarBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
        style->Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
        style->Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
        style->Colors[ImGuiCol_CheckMark] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
        style->Colors[ImGuiCol_SliderGrab] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
        style->Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
        style->Colors[ImGuiCol_Button] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_ButtonHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
        style->Colors[ImGuiCol_ButtonActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
        style->Colors[ImGuiCol_Header] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
        style->Colors[ImGuiCol_HeaderHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
        style->Colors[ImGuiCol_HeaderActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
        style->Colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
        style->Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
        style->Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
        style->Colors[ImGuiCol_PlotLines] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
        style->Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
        style->Colors[ImGuiCol_PlotHistogram] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
        style->Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
        style->Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.25f, 1.00f, 0.00f, 0.43f);
        style->Colors[ImGuiCol_ModalWindowDarkening] = ImVec4(1.00f, 0.98f, 0.95f, 0.73f);
    }
}