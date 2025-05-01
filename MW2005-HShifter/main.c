///
/// MIT License
/// 
/// Copyright (c) 2025 x0reaxeax
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions :
/// 
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
/// 
/// 
/// H-Shifter emulation for Need for Speed: Most Wanted (2005)
/// https://github.com/x0reaxeax/MW2005-HShifter

#include <Windows.h>

#include <stdio.h>
#include <stdint.h>

#include "MinHook/MinHook.h"

#define MWSHIFTER_VERSION_MAJOR 1
#define MWSHIFTER_VERSION_MINOR 0
#define MWSHIFTER_VERSION_PATCH 0

#define STATIC      static
#define NAKED       __declspec(naked)
#define NORETURN    __declspec(noreturn)
#define GLOBAL
#define MAYBE_UNUSED

#define MW_FUNC_SHIFTGEAR           0x006920D0
#define MW_FUNC_SUB_404010          0x00404010
#define MW_OBJ_REGISTRY_CONTAINER   0x0092CD28

#ifdef __cplusplus
typedef bool (__thiscall *fn_ShiftGear)(PDWORD thisptr, int gear);
#else
typedef BOOLEAN (*fn_ShiftGear)(PDWORD thisptr, int gear);
#endif

typedef UINT(WINAPI* GetRawInputData_t)(
    HRAWINPUT hRawInput, 
    UINT uiCommand, 
    LPVOID pData, 
    PUINT pcbSize, 
    UINT cbSizeHeader
);

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
    GEAR_NOCHANGE = 0xFFFFFFFF
} GEAR_SHIFT, *PGEAR_SHIFT;

GLOBAL HANDLE g_hShifterThread = NULL;
GLOBAL MAYBE_UNUSED DWORD g_dwLastGear = 0;
GLOBAL GetRawInputData_t oGetRawInputData = NULL;

DWORD sub_404010 = MW_FUNC_SUB_404010;
fn_ShiftGear ShiftGear = (fn_ShiftGear) MW_FUNC_SHIFTGEAR;

DWORD CallShiftGear(
    DWORD dwTargetGear
);

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
                CallShiftGear(
                    GEAR_NEUTRAL
                );
            }

            if ('0' == vkCode) {
                CallShiftGear(
                    GEAR_REVERSE
                );
            }

            if (vkCode >= '1' && vkCode <= '8') {
                CallShiftGear(
                    vkCode - 47
                );
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

DWORD *__cdecl sub_5D49F0(DWORD *a1, int a2, int a3, DWORD *a4) 
{
    int v4; // esi
    int v5; // ecx
    int v6; // eax
    DWORD *result; // eax

    v4 = a2;
    v5 = (a3 - a2) >> 3;
    while (v5 > 0)
    {
        v6 = v5 / 2;
        if (*(DWORD *) (v4 + 8 * (v5 / 2)) >= *a4)
        {
            v5 /= 2;
        } else
        {
            v4 += 8 * v6 + 8;
            v5 += -1 - v6;
        }
    }
    result = a1;
    *a1 = v4;
    return result;
}

PDWORD sub_5D59F0(DWORD *thisptr, DWORD *a2)
{
    DWORD *v2; // esi
    DWORD *v3; // edi
    int v5; // [esp-10h] [ebp-20h]
    DWORD v6[2]; // [esp+8h] [ebp-8h] BYREF

    v2 = (DWORD *) thisptr[2];
    v3 = a2;
    v5 = thisptr[1];
    v6[0] = (DWORD) a2;
    v6[1] = 0;
    sub_5D49F0(
        (DWORD *) & a2,
        v5, 
        (DWORD) v2, 
        v6
    );
    if (a2 == v2 || (DWORD *) *a2 != v3)
        return 0;
    else
        return (PDWORD) a2[1];
}

DWORD *GetVehicleObject(
    VOID
) {
    /*  call stack
        -------------------------
        * sub_6920D0  (ShiftGear)
        * sub_6A0AA0
        * sub_6AF440
        *  * thisPointer = sub_5D59F0(registryObject, sub_404010)
        * sub_69CE20 
    */


    /*
        * sub_69CE20:
            mov     eax, [ebp+7Ch]      ; pointer to registry container
            test    eax, eax
            jz      loc_69CED9
            mov     ecx, [eax+4]        ; pointer to registry object (this)
            push    offset sub_404010
            call    sub_5D59F0
    */

    DWORD pdwRegistryContainer = *(PDWORD) MW_OBJ_REGISTRY_CONTAINER;
    DWORD pdwThisRegistryObject = *(PDWORD) (pdwRegistryContainer + 4);

    PDWORD pVehicle = sub_5D59F0(
        (PDWORD) pdwThisRegistryObject,
        (PDWORD) sub_404010
    );

    if (NULL == pVehicle) {
        return NULL;
    }

    /*
        * sub_6AF440 => [ return sub_6A0AA0(this - 19, gear, 0); ]:
            push    0
            push    eax
            add     ecx, 0FFFFFFB4h ; -19
            call    sub_6A0AA0
            retn    4
    */ 
    return pVehicle - 19;
}

DWORD CallShiftGear(
    DWORD dwTargetGear
) {
    DWORD *pVehicle = GetVehicleObject();
    if (NULL == pVehicle) {
        return GEAR_NOCHANGE;
    }

    DWORD dwResult;

#ifdef __cplusplus
    dwResult = ShiftGear(
        pVehicle,
        dwTargetGear
    );
#else
    // simulate __thiscall
    __asm __volatile {
        push    dwTargetGear
        mov     ecx, pVehicle
        call    ShiftGear
        mov     dwResult, eax
    }
#endif

    return dwResult;
}

DWORD WINAPI ShifterThread(
    LPVOID lpParam
) {
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
                    "Failed to initialize H-Shifter", 
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