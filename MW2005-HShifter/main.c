#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

#define STATIC      static
#define NAKED       __declspec(naked)
#define NORETURN    __declspec(noreturn)

#define NFSMW_SHIFTGEAR_FUNCTION_OFFSET 0x2920D0

HANDLE  g_hShifterThread = NULL;
DWORD32 g_dwCarObject = 0;
DWORD32 g_dwOriginalShiftGearFunction = 0;

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

    //if (dwRelOffset < INT32_MIN || dwRelOffset > INT32_MAX) {
    //    return 0; // out of range
    //}

    lpOutBuf[0] = 0xE9; // long jump
    lpOutBuf[1] = (BYTE) (dwRelOffset & 0xFF);
    lpOutBuf[2] = (BYTE) ((dwRelOffset >> 8) & 0xFF);
    lpOutBuf[3] = (BYTE) ((dwRelOffset >> 16) & 0xFF);
    lpOutBuf[4] = (BYTE) ((dwRelOffset >> 24) & 0xFF);
    return 5;
}

VOID NAKED NORETURN _Trampoline(
    VOID
) {
    __asm {
        JMP [_GearShiftHook]
        NOP
        NOP
        NOP
    }
}

STATIC CONST BYTE abyOriginalPrologue[] = {
    0x56,                                   // push esi
    0x8B, 0xF1,                             // mov esi, ecx
    0x8B, 0x8E, 0x60, 0x01, 0x00, 0x00,     // mov ecx, [esi+0x160]
};

typedef enum _GEAR_SHIFT {
    GEAR_REVERSE = 0,
    GEAR_NEUTRAL = 1,
    GEAR_FIRST = 2,
    GEAR_SECOND = 3,
    GEAR_THIRD = 4,
    GEAR_FOURTH = 5,
    GEAR_FIFTH = 6,
    GEAR_SIXTH = 7,
    GEAR_SEVENTH = 8,
    GEAR_EIGHTH = 9
} GEAR_SHIFT, *PGEAR_SHIFT;

DWORD WINAPI ShifterThread(
    LPVOID lpParam
) {
    AllocConsole();

    FILE* pFile = NULL;
    freopen_s(&pFile, "CONOUT$", "w", stdout);


    HMODULE hBaseModule = GetModuleHandle(NULL);

    if (NULL == hBaseModule) {
        return EXIT_FAILURE;
    }

    g_dwOriginalShiftGearFunction = (DWORD32) hBaseModule + NFSMW_SHIFTGEAR_FUNCTION_OFFSET;

    fprintf(
        pFile,
        "[*] Trampoline: %08X\n"
        "[*] Hook: %08X\n"
        "[*] Original: %08X\n",
        _Trampoline,
        _GearShiftHook,
        g_dwOriginalShiftGearFunction
    );

    DWORD dwOldProtect = 0;
    if (!VirtualProtect(
        (LPVOID) g_dwOriginalShiftGearFunction,
        sizeof(abyOriginalPrologue),
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    )) {
        fprintf(pFile, "VirtualProtect(): E%lu\n", GetLastError());
        return EXIT_FAILURE;
    }

    VirtualProtect(
        (LPVOID) _GearShiftHook,
        sizeof(abyOriginalPrologue),
        PAGE_EXECUTE_READWRITE,
        &dwOldProtect
    );


    BYTE abyJumpFromTrampolineToHook[5] = { 0 };
    SIZE_T dwJumpSize = GenJump(
        (DWORD32) _GearShiftHook,
        (DWORD32) g_dwOriginalShiftGearFunction,
        abyJumpFromTrampolineToHook
    );
    if (0 == dwJumpSize) {
        fprintf(pFile, "GenJump(1) : 0\n");
        return EXIT_FAILURE;
    }

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

    BYTE abyJumpFromHookToOriginal[5] = { 0 };
    dwJumpSize = GenJump(
        (DWORD32) g_dwOriginalShiftGearFunction + 9,
        (DWORD32) _GearShiftHook + 15,
        abyJumpFromHookToOriginal
    );

    if (0 == dwJumpSize) {
        fprintf(pFile, "GenJump(2) : 0\n");
        return EXIT_FAILURE;
    }

    if (2 == dwJumpSize) {
        memset(
            &abyJumpFromHookToOriginal[2],
            0x90,
            sizeof(abyJumpFromHookToOriginal) - 2
        );
    }

    memcpy(
        (DWORD32) _GearShiftHook + 15,
        abyJumpFromHookToOriginal,
        sizeof(abyJumpFromHookToOriginal)
    );

    while (TRUE) {
        if (0 == g_dwCarObject) {
            Sleep(100); // wait for the car object to be set
            continue;
        }

        DWORD dwCurrentGear = *(DWORD32*)(g_dwCarObject + 0x84);

        *(DWORD32*) (g_dwCarObject + 0x84) = 3;
    }
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
                MessageBoxA(NULL, "Failed to create shifter thread", "Error", MB_OK | MB_ICONERROR);
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