#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include "MinHook/MinHook.h"

#define STATIC      static
#define NAKED       __declspec(naked)
#define NORETURN    __declspec(noreturn)

#define NFSMW_SHIFTGEAR_FUNCTION_OFFSET 0x2920D0

HANDLE  g_hShifterThread = NULL;
DWORD32 g_dwCarObject = 0;
DWORD32 g_dwOriginalShiftGearFunction = 0;
PDWORD32 g_lpdwGearAddress = NULL;

FILE *g_fpStdout = NULL;
FILE *g_fpStderr = NULL;

typedef UINT(WINAPI* GetRawInputData_t)(
    HRAWINPUT hRawInput, 
    UINT uiCommand, 
    LPVOID pData, 
    PUINT pcbSize, 
    UINT cbSizeHeader
);

GetRawInputData_t oGetRawInputData = NULL;

STATIC CONST BYTE abyOriginalPrologue[] = {
    0x56,                                   // push esi
    0x8B, 0xF1,                             // mov esi, ecx
    0x8B, 0x8E, 0x60, 0x01, 0x00, 0x00,     // mov ecx, [esi+0x160]
};

VOID NAKED NORETURN _GearShiftHook(
    VOID
) {
    __asm {
        MOV [g_dwCarObject], ECX            // save 'this' pointer
        PUSH ESI
        MOV ESI, ECX
        MOV ECX, [ESI + 0x160]
        JMP [g_dwOriginalShiftGearFunction + 9] // jump to original function]
    }
}

VOID NAKED NORETURN _Trampoline(
    VOID
) {
    __asm {
        JMP[_GearShiftHook]
        NOP
        NOP
        NOP
    }
}

SIZE_T GenJump(
    DWORD32 dwDestAddr,
    DWORD32 dwSourceAddr,
    LPBYTE lpOutBuf
) {
    DWORD32 dwRelOffset = dwDestAddr - (dwSourceAddr + 2); // assume short jump first

    // short jump
    if (dwRelOffset >= -128 && dwRelOffset <= 127) {
        lpOutBuf[0] = 0xEB; // short jump
        lpOutBuf[1] = (BYTE) (dwRelOffset & 0xFF);
        return 2;
    }

    // long jump
    dwRelOffset = dwDestAddr - (dwSourceAddr + 5);

#ifdef WIN64
    if (dwRelOffset < INT32_MIN || dwRelOffset > INT32_MAX) {
        return 0; // out of range
    }
#endif

    lpOutBuf[0] = 0xE9; // long jump
    lpOutBuf[1] = (BYTE) (dwRelOffset & 0xFF);
    lpOutBuf[2] = (BYTE) ((dwRelOffset >> 8) & 0xFF);
    lpOutBuf[3] = (BYTE) ((dwRelOffset >> 16) & 0xFF);
    lpOutBuf[4] = (BYTE) ((dwRelOffset >> 24) & 0xFF);
    return 5;
}

typedef enum _GEAR_SHIFT {
    GEAR_REVERSE = 0,
    GEAR_NEUTRAL = 1,
    GEAR_FIRST = 2,
    GEAR_SECOND = 3,
    GEAR_THIRD = 4,
    GEAR_FOURTH = 5,
    GEAR_FIFTH = 6,
    GEAR_SIXTH = 7,
    GEAR_SEVENTH = 8
} GEAR_SHIFT, *PGEAR_SHIFT;

UINT WINAPI HookGetRawInputData(
    HRAWINPUT hRawInput,
    UINT uiCommand,
    LPVOID pData,
    PUINT pcbSize,
    UINT cbSizeHeader
) {
    UINT ret = oGetRawInputData(
        hRawInput,
        uiCommand,
        pData,
        pcbSize,
        cbSizeHeader
    );

    if (uiCommand == RID_INPUT && pData != NULL) {
        RAWINPUT* pRaw = (RAWINPUT*) pData;

        if (pRaw->header.dwType == RIM_TYPEKEYBOARD) {
            USHORT vkCode = pRaw->data.keyboard.VKey;

            if ('N' == vkCode) {
                *g_lpdwGearAddress = GEAR_NEUTRAL;
            }

            if ('0' == vkCode) {
                *g_lpdwGearAddress = GEAR_REVERSE;
            }

            if (VK_DELETE == vkCode) {
                printf("[*] Resetting car object..\n");
                g_dwCarObject = 0;
                // regain object pointer, but wait loop here freezes the game
            }

            if (vkCode >= '1' && vkCode <= '8') {
                printf("[*] RawInput: %c pressed\n", vkCode);
                *g_lpdwGearAddress = vkCode - 47;
            }
        }
    }

    return ret;
}

BOOLEAN InstallRawInputHook(
    VOID
) {
    MH_STATUS mhStatus;

    if (MH_OK != (mhStatus = MH_Initialize())) {
        fprintf(
            stderr,
            "MH_Initialize(): E%lu\n",
            mhStatus
        );
        return FALSE;
    }

    HMODULE hUser32 = GetModuleHandleA(
        "user32.dll"
    );

    if (NULL == hUser32) {
        fprintf(
            stderr,
            "GetModuleHandleA(): E%lu\n",
            GetLastError()
        );
        return FALSE;
    }

    PVOID pTarget = GetProcAddress(
        hUser32, 
        "GetRawInputData"
    );

    if (NULL == pTarget) {
        fprintf(
            stderr,
            "GetProcAddress(): E%lu\n",
            GetLastError()
        );
        return FALSE;
    }

    if (MH_OK != (mhStatus = MH_CreateHook(
        pTarget,
        HookGetRawInputData,
        (LPVOID*) &oGetRawInputData
    ))) {
        fprintf(
            stderr,
            "MH_CreateHook(): E%lu\n",
            GetLastError()
        );
        return FALSE;
    }

    if (MH_OK != (mhStatus = MH_EnableHook(
        pTarget
    ))) {
        fprintf(
            stderr,
            "MH_EnableHook(): E%lu\n",
            GetLastError()
        );
        return FALSE;
    }

    return TRUE;
}


DWORD WINAPI ShifterThread(
    LPVOID lpParam
) {
    AllocConsole();
    freopen_s(&g_fpStdout, "CONOUT$", "w", stdout);
    freopen_s(&g_fpStderr, "CONOUT$", "w", stderr);

    if (NULL == g_fpStdout) {
        return EXIT_FAILURE;
    }


    HMODULE hBaseModule = GetModuleHandle(NULL);

    if (NULL == hBaseModule) {
        return EXIT_FAILURE;
    }

    g_dwOriginalShiftGearFunction = (DWORD_PTR) hBaseModule + NFSMW_SHIFTGEAR_FUNCTION_OFFSET;

    DWORD dwOldProtect = 0;
    if (!VirtualProtect(
        (LPVOID) g_dwOriginalShiftGearFunction,
        sizeof(abyOriginalPrologue),
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    )) {
        fprintf(
            stderr,
            "VirtualProtect(): E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    BYTE abyJumpFromTrampolineToHook[5] = { 0 };
    SIZE_T dwJumpSize = GenJump(
        (DWORD32) _GearShiftHook,
        (DWORD32) g_dwOriginalShiftGearFunction,
        abyJumpFromTrampolineToHook
    );

    if (2 == dwJumpSize) {
        memset(
            &abyJumpFromTrampolineToHook[2],
            0x90,
            sizeof(abyJumpFromTrampolineToHook) - 2
        );
    }

    memcpy(
        (LPVOID) g_dwOriginalShiftGearFunction,
        abyJumpFromTrampolineToHook,
        sizeof(abyJumpFromTrampolineToHook)
    );

    VirtualProtect(
        (LPVOID) g_dwOriginalShiftGearFunction,
        sizeof(abyOriginalPrologue),
        dwOldProtect,
        &dwOldProtect
    );

    if (!VirtualProtect(
        (LPVOID) _GearShiftHook,
        sizeof(abyOriginalPrologue),    // whatever
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    )) {
        fprintf(
            stderr,
            "VirtualProtect(): E%lu\n",
            GetLastError()
        );
        return EXIT_FAILURE;
    }

    BYTE abyJumpFromHookToOriginal[5] = { 0 };
    dwJumpSize = GenJump(
        (DWORD32) g_dwOriginalShiftGearFunction + 9,
        (DWORD32) _GearShiftHook + 15,
        abyJumpFromHookToOriginal
    );

    if (2 == dwJumpSize) {
        memset(
            &abyJumpFromHookToOriginal[2],
            0x90,
            sizeof(abyJumpFromHookToOriginal) - 2
        );
    }

    memcpy(
        (LPVOID) ((DWORD32) _GearShiftHook + 15),
        abyJumpFromHookToOriginal,
        sizeof(abyJumpFromHookToOriginal)
    );

    VirtualProtect(
        (LPVOID) _GearShiftHook,
        sizeof(abyOriginalPrologue),    // whatever
        dwOldProtect,
        &dwOldProtect
    );

    while (0 == g_dwCarObject) {
        Sleep(50); // wait for the car object to be set
    }

    g_lpdwGearAddress = (PDWORD) ((DWORD32) g_dwCarObject + 0x84);
    printf(
        "[*] Car object: %08X\n"
        "[*] Gear address: %08X\n",
        (DWORD_PTR) g_dwCarObject,
        (DWORD_PTR) g_lpdwGearAddress
    );

    if (!InstallRawInputHook()) {
        printf(
            "[-] Failed to install raw input hook\n"
        );
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hShifterThread = CreateThread(
                NULL,
                0,
                ShifterThread,
                NULL,
                0,
                NULL
            ); 

            if (NULL == g_hShifterThread) {
                MessageBoxA(
                    NULL, 
                    "Failed to create shifter thread", 
                    "Error", 
                    MB_OK | MB_ICONERROR
                );
                return FALSE;
            }
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}