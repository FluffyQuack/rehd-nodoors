/**************************************************************************

                Resident Evil HD Remaster / Resident Evil 0 HD Remaster - Door
Skip Mod Version 1.5

                Written by FluffyQuack

                --Change log--
                v1.51:
                - Support for new RE0 patch.

                v1.5:
                - Code cleanup
                - Changed compiler so the program won't be detected as false
positives in anti-virus

                v1.41:
                - Removed admin check

                v1.4:
                - Updated offsets to work with latest releases of RE HD and RE0
HD.

                v1.3:
                - Added RE0 HD door skip.
                - Fixed a bug with command line arguments.

**************************************************************************/
#include <stdio.h>
#include <string.h>
#include <windows.h>

#define REHD 0
#define RE0 1

const char szREHDExecutable[] = "bhd.exe";
const char szRE0Executable[] = "re0hd.exe";
BYTE readBuffer[100];
BYTE REHD_Pattern[5] = { 0x8B, 0x46, 0x48, 0x85, 0xC0 };
BYTE REHD_DoorLoop[5] = { 0xE9, 0x9F, 0x00, 0x00, 0x00 };
BYTE REHD_DoorEvent[] = { 0xE9, 0x7E, 0x00, 0x00, 0x00 };
BYTE REHD_DoorEventReturn[] = {
    0x5F, 0xC7, 0x86, 0x84, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x5E, 0x5D, 0x5B, 0xC2, 0x10, 0x00
};
BYTE REHD_LiftFix[1] = { 0xFA };

/* Offsets for release version
DWORD REHD_Patches[12] =
{
                0x41CD53, (DWORD) REHD_DoorLoop, sizeof(REHD_DoorLoop),
                0x41CEF5, (DWORD) REHD_DoorEvent, sizeof(REHD_DoorEvent),
                0x41D0CF, (DWORD) REHD_DoorEventReturn,
sizeof(REHD_DoorEventReturn), 0x60E789 + 1, (DWORD) REHD_LiftFix,
sizeof(REHD_LiftFix)
};
*/

// Offsets for patch released on 2018/10/19
DWORD REHD_Patches[12] = {
    0x41CD83, (DWORD)REHD_DoorLoop, sizeof(REHD_DoorLoop),
    0x41CF35, (DWORD)REHD_DoorEvent, sizeof(REHD_DoorEvent),
    0x41D10F, (DWORD)REHD_DoorEventReturn, sizeof(REHD_DoorEventReturn),
    0x611A19 + 1, (DWORD)REHD_LiftFix, sizeof(REHD_LiftFix)
};

/* Pattern for release version
BYTE RE0_Pattern[] =
{
                0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0xDC,
0xA4, 0xCB, 0x00, 0xF3
};
*/

/*//Pattern for patch on 2018/10/19
BYTE RE0_Pattern[] =
{
                0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0x64,
0xA4, 0xCB, 0x00, 0xF3
};
*/

// Pattern for patch around 2025/03
BYTE RE0_Pattern[] = { 0xF3, 0x0F, 0x10, 0x40, 0x38, 0xF3, 0x0F, 0x59, 0x05, 0x14, 0xA4, 0xCB, 0x00, 0xF3 };

BYTE RE0_DoorFloatMinusOne[] = { 0xC7, 0x47, 0x2C, 0x00, 0x00, 0x80, 0xBF, 0xF3, 0x0F, 0x10, 0x47, 0x2C, 0xEB, 0x1C };
BYTE RE0_NoDoorSounds[] = { 0xC3, 0x90, 0x90 };

/* Offsets for release version
DWORD RE0_Patches[12] =
{
                0x552DB3, (DWORD)RE0_DoorFloatMinusOne,
sizeof(RE0_DoorFloatMinusOne), 0x552DB3 + sizeof(RE0_DoorFloatMinusOne), 0, 28,
                0x5534D0, (DWORD)RE0_NoDoorSounds, sizeof(RE0_NoDoorSounds),
                0x5529D0, 0, 6,
};
*/

/* //Offsets for patch released on 2018/10/19
DWORD RE0_Patches[12] =
{
                0x552B93, (DWORD) RE0_DoorFloatMinusOne,
sizeof(RE0_DoorFloatMinusOne), 0x552B93 + sizeof(RE0_DoorFloatMinusOne), 0, 28,
                0x5532B0, (DWORD) RE0_NoDoorSounds, sizeof(RE0_NoDoorSounds),
                0x5527B0, 0, 6,
};
*/

// Offsets for patch released around 2025/03
DWORD RE0_Patches[12] = {
    0x552A13,
    (DWORD)RE0_DoorFloatMinusOne,
    sizeof(RE0_DoorFloatMinusOne),
    0x552A13 + sizeof(RE0_DoorFloatMinusOne),
    0,
    28,
    0x553130,
    (DWORD)RE0_NoDoorSounds,
    sizeof(RE0_NoDoorSounds),
    0x552630,
    0,
    6,
};

UINT MemoryReadOrWrite(DWORD dwAddress, LPVOID lpBuffer, UINT nBytes, BOOL bWrite)
{
    SIZE_T uiBytes = 0;

    if (bWrite) {
        DWORD Protection;
        if (VirtualProtect((LPVOID)dwAddress, nBytes, PAGE_EXECUTE_READWRITE, &Protection)) {
            memcpy((LPVOID)dwAddress, lpBuffer, nBytes);
            uiBytes = nBytes;
            VirtualProtect((LPVOID)dwAddress, nBytes, Protection, &Protection);
        }
    } else {
        memcpy(lpBuffer, (LPVOID)dwAddress, nBytes);
        uiBytes = nBytes;
    }

    return uiBytes;
}

static BOOL PatternComparison(BYTE* compare1, BYTE* compare2, UINT size)
{
    for (UINT i = 0; i < size; i++) {
        if (compare1[i] != compare2[i])
            return FALSE;
    }
    return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    // Perform actions based on the reason for calling.
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
        TCHAR ProcessFileName[MAX_PATH];
        GetModuleFileName(NULL, ProcessFileName, MAX_PATH);
        char* LastSeparator = strrchr(ProcessFileName, '\\');
        if (LastSeparator == NULL) {
            OutputDebugStringA("Could not determine exe name");
            return TRUE;
        }

        char* BaseName = LastSeparator + 1;
        OutputDebugStringA("Mod Loaded");
        OutputDebugStringA(BaseName);

        int game = -1;

        if (_stricmp(BaseName, szREHDExecutable) == 0) {
            game = REHD;
        } else if (_stricmp(BaseName, szRE0Executable) == 0) {
            game = RE0;
        }

        if (game == -1) {
            OutputDebugStringA("Failed to detect game type");
            return TRUE;
        }

        BYTE *origPattern, *moddedPattern;
        DWORD *patches, patternSize, patchesSize;
        if (game == REHD) {
            origPattern = REHD_Pattern;
            moddedPattern = REHD_DoorLoop;
            patches = REHD_Patches;
            patternSize = sizeof(REHD_Pattern);
            patchesSize = sizeof(REHD_Patches) / 4;
        } else if (game == RE0) {
            origPattern = RE0_Pattern;
            moddedPattern = RE0_DoorFloatMinusOne;
            patches = RE0_Patches;
            patternSize = sizeof(RE0_Pattern);
            patchesSize = sizeof(RE0_Patches) / 4;
        }

        DWORD Num = MemoryReadOrWrite(patches[0], readBuffer, patternSize, FALSE);
        // Check if the read pattern is different than the original
        // non-modified pattern
        if (PatternComparison(readBuffer, origPattern, patternSize) == 0) {
            // Check if the read pattern is different than the door skip
            // modded pattern (if true, then we're probably hooking onto a
            // different version of the game)
            if (PatternComparison(readBuffer, moddedPattern, patternSize) == 0) {
                OutputDebugStringA("Door Skip: Wrong game version");
            } else {
                OutputDebugStringA("Door Skip: Already active");
            }
        } else {
            SIZE_T uBytes;
            OutputDebugStringA("Door Skip: Activating");
            for (UINT i = 0; i < patchesSize; i += 3) {
                // patches[i + 0] = Address we write to
                // patches[i + 1] = Pointer to pattern to write
                // patches[i + 2] = Size of pattern

                // If there's no pointer to pattern to
                // overwrite with, then we write NOPs
                if (patches[i + 1] == 0) {
                    BYTE nop = 0x90;
                    for (DWORD j = 0; j < patches[i + 2]; j++) {
                        uBytes = MemoryReadOrWrite(patches[i + 0] + j, (LPVOID)&nop, 1, TRUE); // Write one NOP
                        if (uBytes == 0) {
                            OutputDebugStringA("Door Skip: Failed write");
                            return TRUE;
                        }
                    }
                } else { // Write a pre-defined pattern
                    uBytes = MemoryReadOrWrite(patches[i + 0], (LPVOID)patches[i + 1], patches[i + 2], TRUE);
                    if (!uBytes) {
                        OutputDebugStringA("Door Skip: Failed write");
                        return TRUE;
                    }
                }
            }
        }

        OutputDebugStringA("Door Skip: Successfully patched");

        break;
    }
    case DLL_PROCESS_DETACH: {
        if (lpvReserved != NULL) {
            break; // do not do cleanup if process termination scenario
        }

        break;
    }
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}
