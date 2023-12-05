#![feature(core_intrinsics)]
#![allow(non_snake_case, non_camel_case_types)]
use std::arch::asm;
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uchar, c_ulong, c_void, CStr, CString};
use std::fs::{File, read, write};
use std::io::Read;
use std::mem::{transmute, transmute_copy};
use std::path::Path;
use std::{ptr, thread};
use std::ptr::{addr_of, slice_from_raw_parts};
use std::thread::JoinHandle;
use std::time::Duration;

static DLL: &[u8] = include_bytes!("../dll.dll");
fn main() { unsafe{
    println!("size of list entry: {}", std::mem::size_of::<LIST_ENTRY>());
    if !(Path::new("dll.dll").exists()) { // write the dll to the path of execution if it doesnt already exist (this makes it easier to test in virustotal.com)
        write("dll.dll",DLL);
    }
    let action_thread = action_thread();
    std::thread::sleep(Duration::from_millis(500));
    let load_result = LoadLibraryA(CString::new("dll").unwrap().as_ptr());
    action_thread.join();
}}

unsafe fn action_thread() -> JoinHandle<()> {
    let t2 = thread::spawn(
        move || {
            thread::sleep(Duration::from_secs(2)); // sleep for long enough to be pretty certain the call to LoadLibrary has failed
            let hello_offset = get_offset_of_hello().expect("no offset found"); //I found this by casting the function pointer into a u32 and printing it
            println!("calculated offset of hello: {hello_offset}");
            asm!{
                "call {0}",
                in(reg) hello_offset
            };
        }
    );
    t2
}

unsafe fn get_offset_of_hello() -> Option<u32> {
    //1. find base address of dll.dll in memory by traversing the LDR within the PEB block
    let dll_base_addr = find_dll_base_addr("dll.dll")?;

    //2. from the base address, traverse the export address table of that dll to find the offset to the hello function
    let dos_header = (dll_base_addr as *const IMAGE_DOS_HEADER); // turn dll base addr into dos header
    // assert_eq!((*dos_header).e_magic,*b"MZ"); // assert that the dos header has been read in correctly by checking the magic string

    let image_nt_header = (dos_header as usize + (*dos_header).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64; // lil bit of pointer arithmetic to find the image nt headers

    // assert_eq!((*image_nt_header).Signature, *b"PE\0\0"); // make sure signature looks ok
    println!("{:?}", &*image_nt_header);

    //3. from the nt headers, find the export tables and iterate through comparing the function names to "hello" until we find the right one
    let export_table_offset = (dll_base_addr as u32 + (*image_nt_header).OptionalHeader.DataDirectory[0].VirtualAddress) as *const IMAGE_EXPORT_DIRECTORY;
    let name_table_offset = dll_base_addr as u32 + (*export_table_offset).AddressOfNames;
    let function_table_offset = dll_base_addr as u32 + (*export_table_offset).AddressOfFunctions;
    let function_names = slice_from_raw_parts(name_table_offset as *const u32, (*export_table_offset).NumberOfNames as usize);
    let function_addrs = slice_from_raw_parts(function_table_offset as *const u32, (*export_table_offset).NumberOfNames as usize);

    for name in (&*function_names).iter().zip(&*function_addrs) { // iterate through the names and function addrs
        let actual_name_addr = dll_base_addr as u32 + *name.0;
        let actual_function_addr = dll_base_addr as u32 +(*name.1);
        let name = CStr::from_ptr(actual_name_addr as *const i8).to_str().ok()?;
        if name == "hello" {
            return Some(actual_function_addr);
        }
    }

    return None;
}

/// finds the import address table in memory to get the base address of dll.dll
unsafe fn find_dll_base_addr(dll_name: &str) -> Option<*mut usize> {
    // pointer to the ldr
    let ldr_pointer: *const u64; //contains head of linked list
    asm!(
    "xor rdx,rdx",
    "mov rdx, gs:[60h]", // the PEB block is at 0x60 in the gs register
    "mov rdx, [rdx+0x18]", // get offset of the ldr field
    "mov rdx, [rdx+0x20]", // should be the offset of the first module in the linked list
    "mov {0}, rdx", // move that pointer into ldr_pointer
    out(reg) ldr_pointer
    );


    let ldr_entry: &LIST_ENTRY = transmute::<*const u64, &LIST_ENTRY>(ldr_pointer); // use transmute to turn a raw pointer into a &LIST_ENTRY type
    let base_addrs = enumerate_ldr(ldr_entry as *const _ as *mut LIST_ENTRY); // hashmap of all the base addresses for each dll that has been loaded
    let dll_addr =  base_addrs.get(dll_name).map(|addr| *addr);
    return dll_addr;
}

/// traverses ldr doubly linked list. its a circular list so it exits when the head equals current_entry and the list has gone full circle
/// returns a hashmap of <dllname>:<dllbase>
unsafe fn enumerate_ldr(start: PLIST_ENTRY) -> HashMap<String,*mut usize> {
    let mut base_addrs:HashMap<String,*mut usize> = HashMap::new();
    let mut current = start;
    loop {
        let current_entry_data_table = current as *mut LDR_DATA_TABLE_ENTRY;
        let name = &(*current_entry_data_table).BaseDllName;
        let base_addr:*mut usize = (*current_entry_data_table).DllBase as *mut usize;
        let dos_header = &*(base_addr as *mut IMAGE_DOS_HEADER);
        if base_addr.is_null() {
            break;
        }
        // println!("{}: base_addr: {:?}, dos_header: {:?}",name.to_string(), base_addr as usize,dos_header);
        base_addrs.insert(name.to_string(),base_addr as *mut _);
        current = (*current).Flink;
        if current == start { break; }
    }
    return base_addrs;
}



#[repr(C)]
#[derive(Debug,Copy, Clone)]
pub struct LIST_ENTRY {
    Flink: PLIST_ENTRY,
    Blink: PLIST_ENTRY,
}
pub type PLIST_ENTRY = *mut LIST_ENTRY;
pub type PRLIST_ENTRY = *mut LIST_ENTRY;

#[repr(C)]
#[derive(Debug)]
pub struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}

impl ToString for UNICODE_STRING {
    fn to_string(&self) -> String {
        let slice = unsafe { std::slice::from_raw_parts(self.Buffer, self.Length as usize / 2) };
        let result = String::from_utf16(slice).unwrap();
        result
    }
}
#[repr(C)]
pub union LIST_ENTRY_2 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    DllBase: *mut c_void, // this is what we are looking for
    EntryPoint: *mut c_void,
    Reserved3: *mut c_void,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Reserved5: [*mut c_void; 3],
    CheckSumOrReserved6: [u8; 4],
    TimeDateStamp: c_ulong,
}
#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: [u8;2], // Magic number
    pub e_cblp: u16, // Bytes on last page of file
    pub e_cp: u16, // Pages in file
    pub e_crlc: u16, // Relocations
    pub e_cparhdr: u16, // Size of header in paragraphs
    pub e_minalloc: u16, // Minimum extra paragraphs needed
    pub e_maxalloc: u16, // Maximum extra paragraphs needed
    pub e_ss: u16, // Initial (relative) SS value
    pub e_sp: u16, // Initial SP value
    pub e_csum: u16, // Checksum
    pub e_ip: u16, // Initial IP value
    pub e_cs: u16, // Initial (relative) CS value
    pub e_lfarlc: u16, // File address of relocation table
    pub e_ovno: u16, // Overlay number
    pub e_res: [u16; 4], // Reserved words
    pub e_oemid: u16, // OEM identifier (for e_oeminfo)
    pub e_oeminfo: u16, // OEM information; e_oemid specific
    pub e_res2: [u16; 10], // Reserved words
    pub e_lfanew: u32, // File address of new exe header
}

#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: [u8;4],
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}
#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Debug)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}
#[derive(Debug)]
pub enum HINSTANCE {}
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpFileName: *const c_char) -> *mut HINSTANCE;
    pub fn GetLastError() -> c_ulong;
    pub fn FreeLibrary(hLibModule: *mut HINSTANCE) -> u8;
}
