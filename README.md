# ContionMig's Millin-Injector

[[My Website]](http://sagaanpillai.com/)

Millin Injector offers many features which can aid in creating usermode cheats. Its meant to be light weight and allow users to view things  such as loaded modules, imports and other smaller things

# Screenshots
![ScreenShot](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_1.png)
![ScreenShot2](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_2.png)

# Features
# Processes Tab
- Simple Table For Processes
- Info Displayed: PID, EXE Name, Window Name, Ram Used and Full Path
- Buttons Allows You To: Select Program For Injection, Terminate Program or Refresh List 
- Allows You To Switch To NtQueryVirtualMemory For Checking Loaded Modules

![ScreenShot3](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_2.png)

# Modules Tab
- Simple Table For Modules ( From Selected Process )
- Info Displayed: DLL Name, Base Address, Base Size and Full Path
- Buttons Allows You To: Select Module To Check Imports

![ScreenShot4](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_3.png)

# Imports Tab
- Simple Display Of Imports Found From File
- Info Displayed: RVA, Original First Thunk, Name Of Module, Name Of Imported Function
( Remember that this is being parsed through file, not through running process )

![ScreenShot5](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_4.png)

# Injection Tab
- Offers 3 Injections Methods
 - Thread Creation
  - 3 Methods Of Creating Thread
    - CreateRemoteThread
    - NtCreateThreadEx
    - RtlCreateUserThread
  - Delayed Injection
  - Using Full Handle Perms ( Either Uses Needed Perms or PROCESS_ALL_ACCESS )
  - Manual Map
  - Changes Started Thread's Start Address
  - Hides Started Thread From Debuggers ( NtSetInformationThread )
  - Clears Loaded Module's PE Headers
  - Unlinks The Loaded Module From 3 Lists
    - Load Order List ( InLoadOrderModuleList )
    - Memory Order List ( InMemoryOrderModuleList )
    - Initialziation Order List ( InInitializationOrderModuleList )
- APC Injection
- SetWindowsHook
( Drag & Drop Your DLL Into The Process's Window To Make It Go Into DLL Path )

![ScreenShot6](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_1.png)

# Console Tab
- Displays the Default Console From IMGUI
- Only One Proper Command: REFRESHPROCESS 
![ScreenShot7](https://github.com/ContionMig/Millin-Injector/blob/master/Millin%20Injector/ScreenShots/Screenshot_5.png)

# TO-DO
- Add Thread Hi-Jacking
- Optimize Code

# Credits
Rendering: https://github.com/ocornut/imgui
ImGui Extentions: https://gist.github.com/Flix01/2c6e06b4a4f93016c334
Unlinking Modules: https://github.com/SLAUC91/DLLHiding
ImGui Themes: https://github.com/ocornut/imgui/issues/707
Cleaning PEB: http://www.rohitab.com/discuss/topic/42077-module-pebldr-hiding-all-4-methods-x64/
Antis: https://github.com/LordNoteworthy/al-khaser
MM: github.com/ItsJustMeChris/Manual-Mapper/blob/master/Heroin/needle.h
