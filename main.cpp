/**************************************************************************

	Resident Evil HD Remaster / Resident Evil 0 HD Remaster - Door Skip Mod
	Version 1.5
	
	Written by FluffyQuack

	--Change log--
	v1.5:
	- Code cleanup
	- Changed compiler to VS2008 so the program won't be detected as false positives in anti-virus

	v1.41:
	- Removed admin check

	v1.4:
	- Updated offsets to work with latest releases of RE HD and RE0 HD.
	
	v1.3:
	- Added RE0 HD door skip.
	- Fixed a bug with command line arguments.

**************************************************************************/
#include <Windows.h>
#include <TlHelp32.h>

#define WinWidth 410
#define WinHeight 40
#define REHD 0
#define RE0 1

HWND hWin;
HFONT hFont;
RECT rc;
PAINTSTRUCT ps;
MSG msg;
WNDCLASSEX wcex;
DWORD ProcessId;
DWORD game;

#define IDT_HELLO 1
#define IDT_MAIN 2
#define IDT_EXIT 3
enum
{
	IDS_HELLO,
	IDS_WAITING,
	IDS_FAILED_READ,
	IDS_FAILED_WRITE,
	IDS_FAILED_VERSION,
	IDS_ALREADY_ACTIVE,
	IDS_ACTIVATED,
};
UINT uiStatus = IDS_HELLO;
const char *sStatus[] =
{
	"Door Skip mod by FluffyQuack (v1.5)", //IDS_HELLO
	"Waiting for game to start...", //IDS_WAITING
	"Error: Couldn't read game memory.", //IDS_FAILED_READ
	"Error: Couldn't write to game memory.", //IDS_FAILED_WRITE
	"Error: Unsupported game version.", //IDS_FAILED_VERSION
	"Mod is already active!", //IDS_ALREADY_ACTIVE
	"Mod succesfully activated!" //IDS_ACTIVATED
};

const char szClassName[] = "FluffyQuack";
const char szWindowName[] = "Door Skip mod";
const char szREHDExecutable[] = "bhd.exe";
const char szRE0Executable[] = "re0hd.exe";
BYTE readBuffer[100];
BYTE REHD_Pattern[5] =
{
	0x8B, 0x46, 0x48, 0x85, 0xC0
};
BYTE REHD_DoorLoop[5] =
{
	0xE9, 0x9F, 0x00, 0x00, 0x00
};
BYTE REHD_DoorEvent[] =
{
	0xE9, 0x7E, 0x00, 0x00, 0x00
};
BYTE REHD_DoorEventReturn[] =
{
	0x5F, 0xC7, 0x86, 0x84, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x5E, 0x5D, 0x5B, 0xC2, 0x10, 0x00
};
BYTE REHD_LiftFix[1] =
{
	0xFA
};

/* Offsets for release version
DWORD REHD_Patches[12] =
{                             
	0x41CD53, (DWORD) REHD_DoorLoop, sizeof(REHD_DoorLoop),
	0x41CEF5, (DWORD) REHD_DoorEvent, sizeof(REHD_DoorEvent),
	0x41D0CF, (DWORD) REHD_DoorEventReturn, sizeof(REHD_DoorEventReturn),
	0x60E789 + 1, (DWORD) REHD_LiftFix, sizeof(REHD_LiftFix)
};
*/

//Offsets for patch released on 2018/10/19
DWORD REHD_Patches[12] =
{
	0x41CD83, (DWORD)REHD_DoorLoop, sizeof(REHD_DoorLoop),
	0x41CF35, (DWORD)REHD_DoorEvent, sizeof(REHD_DoorEvent),
	0x41D10F, (DWORD)REHD_DoorEventReturn, sizeof(REHD_DoorEventReturn),
	0x611A19 + 1, (DWORD)REHD_LiftFix, sizeof(REHD_LiftFix)
};

/* Pattern for release version
BYTE RE0_Pattern[] =
{
	0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0xDC, 0xA4, 0xCB, 0x00, 0xF3
};
*/

//Pattern for patch on 2018/10/19
BYTE RE0_Pattern[] =
{
	0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0x64, 0xA4, 0xCB, 0x00, 0xF3
};

BYTE RE0_DoorFloatMinusOne[] = 
{
	0xC7, 0x47, 0x2C, 0x00, 0x00, 0x80, 0xBF, 0xF3, 0x0F, 0x10, 0x47, 0x2C, 0xEB, 0x1C
};
BYTE RE0_NoDoorSounds[] =
{
	0xC3, 0x90, 0x90
};

/* Offsets for release version
DWORD RE0_Patches[12] =
{
	0x552DB3, (DWORD)RE0_DoorFloatMinusOne, sizeof(RE0_DoorFloatMinusOne),
	0x552DB3 + sizeof(RE0_DoorFloatMinusOne), 0, 28,
	0x5534D0, (DWORD)RE0_NoDoorSounds, sizeof(RE0_NoDoorSounds),
	0x5529D0, 0, 6,
};
*/

//Offsets for patch released on 2018/10/19
DWORD RE0_Patches[12] =
{
	0x552B93, (DWORD) RE0_DoorFloatMinusOne, sizeof(RE0_DoorFloatMinusOne),
	0x552B93 + sizeof(RE0_DoorFloatMinusOne), 0, 28,
	0x5532B0, (DWORD) RE0_NoDoorSounds, sizeof(RE0_NoDoorSounds),
	0x5527B0, 0, 6,
};

/*BOOL IsAdmin()
{
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	BOOL bAdmin = FALSE;
	PSID Admins;

	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins))
	{
		CheckTokenMembership(NULL, Admins, &bAdmin);
		FreeSid(Admins);
	}
	return bAdmin;
}*/

DWORD GetProcessId(LPCSTR szProcessName)
{
	PROCESSENTRY32 pe32;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnap != INVALID_HANDLE_VALUE)
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(hSnap, &pe32))
		{
			do
			{
				if(!lstrcmpi(pe32.szExeFile, szProcessName))
				{
					CloseHandle(hSnap);
					return pe32.th32ProcessID;
				}
			}
			while(Process32Next(hSnap, &pe32));
		}
		CloseHandle(hSnap);	
	}
	return 0;	
}

int ShowMessage(LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	MSGBOXPARAMS mbp;

	mbp.cbSize = sizeof(MSGBOXPARAMS);
	mbp.hwndOwner = HWND_DESKTOP;
	mbp.hInstance = GetModuleHandle(NULL);
	mbp.lpszText = lpText;
	mbp.lpszCaption = lpCaption;
	mbp.dwStyle = uType | MB_TOPMOST;
	mbp.lpszIcon = MAKEINTRESOURCE(100);
	mbp.dwContextHelpId = 0;
	mbp.lpfnMsgBoxCallback = NULL;
	mbp.dwLanguageId = LANG_ENGLISH;
	return MessageBoxIndirect(&mbp);
}

UINT MemoryReadOrWrite(HANDLE hProcess, DWORD dwAddress, LPVOID lpBuffer, UINT nBytes, BOOL bWrite)
{
	SIZE_T uiBytes = 0;

	if(hProcess != INVALID_HANDLE_VALUE)
	{
		if(bWrite)
		{
			DWORD Protection;
			if (VirtualProtectEx(hProcess, (LPVOID) dwAddress, nBytes, PAGE_EXECUTE_READWRITE, &Protection))
			{
				WriteProcessMemory(hProcess, (LPVOID) dwAddress, (LPCVOID) lpBuffer, nBytes, &uiBytes);
				VirtualProtectEx(hProcess, (LPVOID) dwAddress, nBytes, Protection, &Protection);
			}
		}
		else
			ReadProcessMemory(hProcess, (LPVOID) dwAddress, lpBuffer, nBytes, &uiBytes);
	}

	return uiBytes;
}

static BOOL PatternComparison(BYTE *compare1, BYTE *compare2, UINT size)
{
	for(UINT i = 0; i < size; i++)
	{
		if(compare1[i] != compare2[i])
			return false;
	}
	return true;
}

LRESULT CALLBACK WinProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
		case WM_CREATE:
			hFont = CreateFontA(28, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH, "Comic Sans MS");
			SetTimer(hWnd, IDT_HELLO, 4000, NULL);
			break;

		case WM_TIMER:
			if(wParam == IDT_MAIN || wParam == IDT_HELLO)
			{
				for(game = 0; game < 2; game++)
				{
					if(game == REHD)
						ProcessId = GetProcessId(szREHDExecutable);
					else if(game == RE0)
						ProcessId = GetProcessId(szRE0Executable);

					if(ProcessId)
						break;
				}
			}

			if(wParam == IDT_MAIN || (wParam == IDT_HELLO && ProcessId))
			{
				if(ProcessId)
				{
					BYTE *origPattern, *moddedPattern;
					DWORD *patches, patternSize, patchesSize;
					if(game == REHD)
					{
						origPattern = REHD_Pattern;
						moddedPattern = REHD_DoorLoop;
						patches = REHD_Patches;
						patternSize = sizeof(REHD_Pattern);
						patchesSize = sizeof(REHD_Patches) / 4;
					}
					else if(game == RE0)
					{
						origPattern = RE0_Pattern;
						moddedPattern = RE0_DoorFloatMinusOne;
						patches = RE0_Patches;
						patternSize = sizeof(RE0_Pattern);
						patchesSize = sizeof(RE0_Patches) / 4;
					}

					KillTimer(hWnd, wParam);
					Sleep(1000);

					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId); //This used to be "PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ" but changing it to "PROCESS_ALL_ACCESS" reduces the amount of false positives by anti-virus programs because I have no idea how any of this works it makes no sense aaaaargh
					
					DWORD Num = MemoryReadOrWrite(hProcess, patches[0], readBuffer, patternSize, false);
					if(Num != patternSize)
					{
						uiStatus = IDS_FAILED_READ;
					}
					else
					{
						if(PatternComparison(readBuffer, origPattern, patternSize) == 0) //Check if the read pattern is different than the original non-modified pattern
						{
							if(PatternComparison(readBuffer, moddedPattern, patternSize) == 0) //Check if the read pattern is different than the door skip modded pattern (if true, then we're probably hooking onto a different version of the game)
								uiStatus = IDS_FAILED_VERSION;
							else
								uiStatus = IDS_ALREADY_ACTIVE;
						}
						else
						{
							SIZE_T uBytes;
							uiStatus = IDS_ACTIVATED;
							for(UINT i = 0; i < patchesSize; i += 3)
							{
								//patches[i + 0] = Address we write to
								//patches[i + 1] = Pointer to pattern to write
								//patches[i + 2] = Size of pattern
								if(patches[i + 1] == 0) //If there's no pointer to pattern to overwrite with, then we write NOPs
								{
									BYTE nop = 0x90;
									for(DWORD j = 0; j < patches[i + 2]; j++)
									{
										uBytes = MemoryReadOrWrite(hProcess, patches[i + 0] + j, (LPVOID) &nop, 1, true); //Write one NOP
										if(uBytes == 0)
										{
											uiStatus = IDS_FAILED_WRITE;
											break;
										}
									}
									if(uiStatus == IDS_FAILED_WRITE)
										break;
								}
								else //Write a pre-defined pattern
								{
									uBytes = MemoryReadOrWrite(hProcess, patches[i + 0], (LPVOID) patches[i + 1], patches[i + 2], true);
									if(!uBytes)
									{
										uiStatus = IDS_FAILED_WRITE;
										break;
									}
								}
							}
						}
					}
					
					if(hProcess != INVALID_HANDLE_VALUE)
						CloseHandle(hProcess);

					InvalidateRect(hWnd, NULL, FALSE);
					if (uiStatus != IDS_FAILED_READ && uiStatus != IDS_FAILED_WRITE && uiStatus != IDS_FAILED_VERSION)
					{
						SetTimer(hWnd, IDT_EXIT, 10000, NULL);
					}
				}
			}
			else if (wParam == IDT_HELLO)
			{
				KillTimer(hWnd, IDT_HELLO);
				SetTimer(hWnd, IDT_MAIN, 5000, NULL);
				uiStatus = IDS_WAITING;
				InvalidateRect(hWnd, NULL, FALSE);
			}
			else if (wParam == IDT_EXIT)
			{
				KillTimer(hWnd, IDT_MAIN);
				SendMessage(hWnd, WM_SYSCOMMAND, SC_CLOSE, 0);
			}
			break;

		case WM_KEYDOWN:
			if (wParam == VK_ESCAPE)
			{
				SendMessage(hWnd, WM_SYSCOMMAND, SC_CLOSE, 0);
			}
			break;

		case WM_PAINT:
			BeginPaint(hWnd, &ps);
			HBRUSH hBrush;
			GetClientRect(hWnd, &rc);
			hBrush = CreateSolidBrush(RGB(249, 207, 221));
			FillRect(ps.hdc, &rc, hBrush);
			DeleteObject(hBrush);
			hBrush = CreateSolidBrush(RGB(0, 0, 0));
			FrameRect(ps.hdc, &rc, hBrush);
			DeleteObject(hBrush);
			DrawIconEx(ps.hdc, 4, 4, wcex.hIcon, 32, 32, 0, NULL, DI_NORMAL);
			SelectObject(ps.hdc, hFont);
			SetBkMode(ps.hdc, TRANSPARENT);
			SetTextColor(ps.hdc, RGB(0, 0, 0));
			rc.left = 42;
			rc.top = 6;
			DrawText(ps.hdc, sStatus[uiStatus], -1, &rc, DT_NOCLIP | DT_SINGLELINE);
			EndPaint(hWnd, &ps);
			break;

		case WM_DESTROY:
			DeleteObject(hFont);
			PostQuitMessage(0);
			break;

		case WM_CLOSE:
			DestroyWindow(hWnd);
			break;

		case WM_LBUTTONDOWN:
			SendMessage(hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
			break;

		default:
			return DefWindowProc(hWnd, uMsg, wParam, lParam);
	}
	return 0;
}

BOOLEAN IsCommandSet(LPWSTR Command)
{
	int c;
	LPWSTR *arg;

	arg = CommandLineToArgvW(GetCommandLineW(), &c);
	if(arg)
	{
		c--;
		while(c)
		{
			if(!lstrcmpiW(arg[c], Command))
			{
				return TRUE;
			}
			c--;
		}
	}
	return FALSE;
}

INT APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
	hWin = FindWindow(szClassName, szWindowName);
	if(hWin)
	{
		if(IsIconic(hWin))
		{
			ShowWindow(hWin, SW_RESTORE);
		}
		else
		{
			SetForegroundWindow(hWin);
		}
	}
	else
	{
		/*if (!IsAdmin()) //Did a test and admin rights doeesn't actually seem to be required? I'm removing this check for now.
		{
			ShowMessage("Error: Admin rights required.", szWindowName, MB_OK | MB_USERICON);
		}
		else*/
		{
			if((IsCommandSet(L"-launchRE1") || IsCommandSet(L"-launchREHD")) && GetProcessId("steam.exe") && !GetProcessId(szREHDExecutable))
			{
				if ((int) ShellExecute(NULL, "open", "steam://rungameid/304240", NULL, NULL, SW_SHOWDEFAULT) <= 32)
				{
					ShowMessage("Error: Failed to launch RE HD Remaster.", szWindowName, MB_OK | MB_ICONERROR);
				}
			}
			else if((IsCommandSet(L"-launchRE0") || IsCommandSet(L"-launchRE0HD")) && GetProcessId("steam.exe") && !GetProcessId(szRE0Executable))
			{
				if ((int) ShellExecute(NULL, "open", "steam://rungameid/339340", NULL, NULL, SW_SHOWDEFAULT) <= 32)
				{
					ShowMessage("Error: Failed to launch RE0 HD Remaster.", szWindowName, MB_OK | MB_ICONERROR);
				}
			}

			wcex.cbSize = sizeof(WNDCLASSEX);
			wcex.style = CS_HREDRAW | CS_VREDRAW;
			wcex.lpfnWndProc = WinProc;
			wcex.cbClsExtra = 0;
			wcex.cbWndExtra = 0;
			wcex.hInstance = GetModuleHandle(NULL);
			wcex.hIcon = (HICON) LoadImage(wcex.hInstance, MAKEINTRESOURCE(100), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
			wcex.hCursor = (HCURSOR) LoadImage(NULL, IDC_ARROW, IMAGE_CURSOR, 0, 0, LR_SHARED);
			wcex.hbrBackground = (HBRUSH) (COLOR_BTNFACE + 1);
			wcex.lpszMenuName = NULL;
			wcex.lpszClassName = szClassName;
			wcex.hIconSm = (HICON) LoadImage(wcex.hInstance, MAKEINTRESOURCE(100), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
			RegisterClassEx(&wcex);
			hWin = CreateWindowEx(NULL, szClassName, szWindowName, WS_POPUP | WS_SYSMENU, GetSystemMetrics(SM_CXSCREEN)/2 - WinWidth/2, GetSystemMetrics(SM_CYSCREEN)/2 - WinHeight/2, WinWidth, WinHeight, HWND_DESKTOP, NULL, wcex.hInstance, NULL);
			ShowWindow(hWin, SW_SHOW);
			while (GetMessage(&msg, NULL, 0, 0) > 0)
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}
	ExitProcess(0);
}