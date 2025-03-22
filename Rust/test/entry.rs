#![cfg(windows)]
#![allow(non_snake_case)]

use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{null_mut, null};

use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};

type AbCallFn = unsafe extern "C" fn(*mut c_void, *const usize, usize) -> usize;

const SystemProcessInformation: u32 = 5;

fn main() {

    unsafe {
        let ab_dll = LoadLibraryA("ActiveBreach.dll\0".as_ptr() as *const i8);
        if ab_dll.is_null() {
            println!("[x] failed to load ActiveBreach.dll");
            return;
        }

        let ab_call_ptr = GetProcAddress(ab_dll, "ab_call\0".as_ptr() as *const i8);
        if ab_call_ptr.is_null() {
            println!("[x] failed to resolve ab_call export");
            return;
        }

        let ab_call: AbCallFn = transmute(ab_call_ptr);

        let tag_cstr = std::ffi::CString::new("NtQuerySystemInformation").unwrap();
        let tag_ptr = tag_cstr.as_ptr() as *mut c_void;

        let mut buffer: [u8; 0x10000] = [0; 0x10000];
        let mut return_length: u32 = 0;

        let args: [usize; 4] = [
            SystemProcessInformation as usize,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut return_length as *mut _ as usize,
        ];

        let status = ab_call(tag_ptr, args.as_ptr(), args.len());

        if status == 0 {
            println!("[+] syscall succeeded via ab_call");
            println!("[+] return length: {}", return_length);
        } else {
            println!("[x] syscall failed via ab_call, status: 0x{:X}", status);
        }
    }
}