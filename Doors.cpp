/**************************************************************************

	Resident Evil HD Remaster / Resident Evil 0 HD Remaster - Door Skip Mod
	Version 1.5
	
	Written by FluffyQuack

	--Change log--
	v1.52:
	- Support for new RE1 HD patch.
	- Updated the code to check multiple addresses so it works with multiple versions.

	v1.51:
	- Support for new RE0 patch.

	v1.5:
	- Code cleanup
	- Changed compiler so the program won't be detected as false positives in anti-virus

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
	"Door Skip mod by FluffyQuack (v1.52)", //IDS_HELLO
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

//For versions older than 2026
BYTE REHD_Pattern_2015[5] = //Bigger context: 8B 46 48 85 C0 0F 84 AA 00 00 00 83 B8 F0 00 00
{
	0x8B, 0x46, 0x48, 0x85, 0xC0
};
BYTE REHD_DoorLoop_2015[5] = 
{
	0xE9, 0x9F, 0x00, 0x00, 0x00
};

//For 2026-09 build
BYTE REHD_Pattern_2026[5] = //Bigger context: 8B 77 48 85 F6 0f 84 1C 02 00 00
{
	0x8B, 0x77, 0x48, 0x85, 0xF6
};
BYTE REHD_DoorLoop_2026[5] = //Jump from 0x47C745 to 0x47C95B
{
	0xE9, 0x11, 0x02, 0x00, 0x00
};
//Note, search for this in the future in case it's difficult to find door loop code again: 8B ?? 84 00 00 00 83 ?? 03 77

BYTE REHD_DoorEvent[] = //Bigger context: C7 46 7C 00 00 00 00 C7 86 80 00 00 00 00 00 00 00 C7 86 84 00 00 00 02 00 00 00
{
	0xE9, 0x7E, 0x00, 0x00, 0x00
};
BYTE REHD_DoorEventReturn[] = //Bigger context: 81 7E 78 19 01 00 00 75 07 C7 46 78 03 00 00 00
{
	0x5F, 0xC7, 0x86, 0x84, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x5E, 0x5D, 0x5B, 0xC2, 0x10, 0x00
};
BYTE REHD_LiftFix[1] = //Bigger context: 68 FB 00 00 00 EB 1D 68 F7 00 00 00 EB 16 A1 2C
{
	0xFA
};

#define REHD_PATCHCOUNT 4
DWORD REHD_Patches[REHD_PATCHCOUNT * 2] =
{
	(DWORD)REHD_DoorLoop_2026, sizeof(REHD_DoorLoop_2026),
	(DWORD)REHD_DoorEvent, sizeof(REHD_DoorEvent),
	(DWORD)REHD_DoorEventReturn, sizeof(REHD_DoorEventReturn),
	(DWORD)REHD_LiftFix, sizeof(REHD_LiftFix)
};

#define REHD_ADDRESS_VARIANTS 3
DWORD REHD_Addresses[REHD_ADDRESS_VARIANTS][4] = 
{
	//Release version
	{
		0x41CD53, //REHD_DoorLoop aka pattern
		0x41CEF5, //REHD_DoorEvent
		0x41D0CF, //REHD_DoorEventReturn
		0x60E789 + 1, //REHD_LiftFix
	},

	//2018/10/19 patch
	{
		0x41CD83, //REHD_DoorLoop aka pattern
		0x41CF35, //REHD_DoorEvent
		0x41D10F, //REHD_DoorEventReturn
		0x611A19 + 1, //REHD_LiftFix
	},

	//2026/09 patch
	{
		0x47C745, //REHD_DoorLoop aka pattern
		0x47CA65, //REHD_DoorEvent
		0x47CC3F, //REHD_DoorEventReturn
		0x668A99 + 1, //REHD_LiftFix
	},
};

//Pattern for release version
BYTE RE0_Pattern_Release[] =
{
	0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0xDC, 0xA4, 0xCB, 0x00, 0xF3
};

//Pattern for patch on 2018/10/19
BYTE RE0_Pattern_2018[] =
{
	0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0x64, 0xA4, 0xCB, 0x00, 0xF3
};

//Pattern for patch around 2025/03
BYTE RE0_Pattern_2025[] =
{
	0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0x14, 0xA4, 0xCB, 0x00, 0xF3
};

BYTE RE0_DoorFloatMinusOne[] = 
{
	0xC7, 0x47, 0x2C, 0x00, 0x00, 0x80, 0xBF, 0xF3, 0x0F, 0x10, 0x47, 0x2C, 0xEB, 0x1C
};
BYTE RE0_NoDoorSounds[] =
{
	0xC3, 0x90, 0x90
};

#define RE0_PATCHCOUNT 4
DWORD RE0_Patches[RE0_PATCHCOUNT * 2] =
{
	(DWORD) RE0_DoorFloatMinusOne, sizeof(RE0_DoorFloatMinusOne),
	0, 28,
	(DWORD) RE0_NoDoorSounds, sizeof(RE0_NoDoorSounds),
	0, 6,
};

#define RE0_ADDRESS_VARIANTS 3
DWORD RE0_Addresses[REHD_ADDRESS_VARIANTS][4] = 
{
	//Release version
	{
		0x552DB3, //RE0_DoorFloatMinusOne
		0x552DB3 + sizeof(RE0_DoorFloatMinusOne), //0
		0x5534D0, //RE0_NoDoorSounds
		0x5529D0, //0
	},

	//Offsets for patch released on 2018/10/19
	{
		0x552B93, //RE0_DoorFloatMinusOne
		0x552B93 + sizeof(RE0_DoorFloatMinusOne), //0
		0x5532B0, //RE0_NoDoorSounds
		0x5527B0, //0
	},

	//Offsets for patch released around 2025/03
	{
		0x552A13, //RE0_DoorFloatMinusOne
		0x552A13 + sizeof(RE0_DoorFloatMinusOne), //0
		0x553130, //RE0_NoDoorSounds
		0x552630, //0
	},
};

//GIGANTIC ARRAY OF NOPS
DWORD GIGANTIC_ARRAY_OF_NOPS_AW_YEAH_THIS_ARRAY_IS_SOOOOOO_COOL_WOOOOOW[25];

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
					DWORD *patches, patternSize, patchCount;
					if(game == REHD)
					{
						patches = REHD_Patches;
						patchCount = REHD_PATCHCOUNT;
					}
					else if(game == RE0)
					{
						moddedPattern = RE0_DoorFloatMinusOne;
						patches = RE0_Patches;
						patchCount = RE0_PATCHCOUNT;
					}

					KillTimer(hWnd, wParam);
					Sleep(1500);

					//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId); //This used to be "PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ" but changing it to "PROCESS_ALL_ACCESS" reduces the amount of false positives by anti-virus programs because I have no idea how any of this works it makes no sense aaaaargh
					HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, ProcessId); //This used to be "PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ" but changing it to "PROCESS_ALL_ACCESS" reduces the amount of false positives by anti-virus programs because I have no idea how any of this works it makes no sense aaaaargh
					
					//Cycle between multiple address to see if we can find the correct one, starting with the newest address
					int addressIdx;
					DWORD curAddress;
					if(game == REHD)
					{
						addressIdx = REHD_ADDRESS_VARIANTS - 1;
						curAddress = REHD_Addresses[addressIdx][0];
					}
					else if(game == RE0)
					{
						addressIdx = RE0_ADDRESS_VARIANTS - 1;
						curAddress = RE0_Addresses[addressIdx][0];
					}

					while(1)
					{
						//Choose pattern that's appropriate for current version
						if(game == REHD)
						{
							if(addressIdx == 2) //2026-09 build
							{
								origPattern = REHD_Pattern_2026;
								moddedPattern = REHD_DoorLoop_2026;
								patternSize = sizeof(REHD_Pattern_2026);
								REHD_Patches[0] = (DWORD) REHD_DoorLoop_2026;
								REHD_Patches[1] = sizeof(REHD_DoorLoop_2026);
							}
							else //2015->2018 builds
							{
								origPattern = REHD_Pattern_2015;
								moddedPattern = REHD_DoorLoop_2015;
								patternSize = sizeof(REHD_Pattern_2015);
								REHD_Patches[0] = (DWORD) REHD_DoorLoop_2015;
								REHD_Patches[1] = sizeof(REHD_DoorLoop_2015);
							}
						}
						else if(game == RE0)
						{
							if(addressIdx == 2) //2025-03 build
							{
								origPattern = RE0_Pattern_2025;
								patternSize = sizeof(RE0_Pattern_2025);
							}
							else if(addressIdx == 1) //2018-10 build
							{
								origPattern = RE0_Pattern_2018;
								patternSize = sizeof(RE0_Pattern_2018);
							}
							else //Release build
							{
								origPattern = RE0_Pattern_Release;
								patternSize = sizeof(RE0_Pattern_Release);
							}
						}

						//Check for pattern
						DWORD Num = MemoryReadOrWrite(hProcess, curAddress, readBuffer, patternSize, false);
						if(Num != patternSize)
						{
							uiStatus = IDS_FAILED_READ;
							goto checkNextAddress;
						}

						if(PatternComparison(readBuffer, origPattern, patternSize)) //We found a valid match for pattern
						{
							//Apply patches
							SIZE_T uBytes;
							uiStatus = IDS_ACTIVATED;
							for(UINT i = 0; i < patchCount; i++)
							{
								DWORD patchPtr = patches[(i * 2) + 0]; //Pointer to patch data
								DWORD patchSize = patches[(i * 2) + 1]; //Size of patch data
								if(game == REHD) curAddress = REHD_Addresses[addressIdx][i];
								else if(game == RE0) curAddress = RE0_Addresses[addressIdx][i];
								
								if(patchPtr == 0) //If there's no pointer to pattern to overwrite with, then we write NOPs
								{
									uBytes = MemoryReadOrWrite(hProcess, curAddress, (LPVOID) GIGANTIC_ARRAY_OF_NOPS_AW_YEAH_THIS_ARRAY_IS_SOOOOOO_COOL_WOOOOOW, patchSize, true);
									if(!uBytes)
									{
										uiStatus = IDS_FAILED_WRITE;
										goto patchDone;
									}
								}
								else //Write a pre-defined pattern
								{
									uBytes = MemoryReadOrWrite(hProcess, curAddress, (LPVOID) patchPtr, patchSize, true);
									if(!uBytes)
									{
										uiStatus = IDS_FAILED_WRITE;
										goto patchDone;
									}
								}
							}

							uiStatus = IDS_ACTIVATED;
							goto patchDone;
						}
						else if(PatternComparison(readBuffer, moddedPattern, patternSize)) //We found a valid match for a modified pattern
						{
							uiStatus = IDS_ALREADY_ACTIVE;
							goto patchDone;
						}

					checkNextAddress:
						addressIdx--;
						if(addressIdx < 0)
						{
							uiStatus = IDS_FAILED_VERSION;
							goto patchDone; //We failed to find a matching starting pattern
						}
					}
					
				patchDone:
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
	if (arg)
	{
		c--;
		while (c)
		{
			if (!lstrcmpiW(arg[c], Command))
			{
				return TRUE;
			}
			c--;
		}
	}
	return FALSE;
}

void Entry()
{
	hWin = FindWindow(szClassName, szWindowName);

	//Fill in the PHAT super duper ultra mega hyper huge array of awesomeness I LIKE BIG ARRAYS AND I CANNOT LIE
	for(int FREE_VARIABLE_NAME = 0; FREE_VARIABLE_NAME < 25; FREE_VARIABLE_NAME++) GIGANTIC_ARRAY_OF_NOPS_AW_YEAH_THIS_ARRAY_IS_SOOOOOO_COOL_WOOOOOW[FREE_VARIABLE_NAME] = 2425393296;

	if (hWin)
	{
		if (IsIconic(hWin))
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
			if((IsCommandSet(L"-launchRE1") || IsCommandSet(L"-launchREHD") || IsCommandSet(L"-launchRE1HD")) && GetProcessId("steam.exe") && !GetProcessId(szREHDExecutable))
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