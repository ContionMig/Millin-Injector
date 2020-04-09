#include "Common.h"

#include "AntiDebug.h"
#include "AntiDump.h"
#include "AntiVM.h"

int main()
{
    ErrorLogs::LogFiles("Welcome To Millin Injector");
    ErrorLogs::LogFiles("Current Path: %s", Helpers::CurrentPath().c_str());
    ErrorLogs::LogFiles("Program Ran As Admin: %s", Helpers::RanAsAdmin() ? "True" : "False");

    ErrorLogs::LogFiles("Starting Threads", Helpers::CurrentPath().c_str());
    Threads::hRenderThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Threads::RenderThread, NULL, NULL, &Threads::RenderThreadID);
    ErrorLogs::LogFiles("All Threads Started");

    FreeConsole();

    Process::RefreshProcessList();
    ErrorLogs::LogFiles("Looping Main", Helpers::CurrentPath().c_str());
    while (1)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
}
