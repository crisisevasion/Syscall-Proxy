use std::env;
use std::ffi::{OsString, OsStr};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::ptr::{null, null_mut};

use winapi::um::fileapi::{CreateFileW, GetFileSize, ReadFile, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree};
use winapi::shared::minwindef::{DWORD, UINT, MAX_PATH};
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_READ, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, MEM_RELEASE};
use winapi::um::sysinfoapi::GetSystemDirectoryW;

use crate::internal::crypto::coder::{decode, ENC};
use crate::internal::err::fatal_err;

pub fn build_sys32_path(encoded: &[u16]) -> Vec<u16> {
    let windir = env::var_os("SystemRoot").unwrap_or_else(|| env::var_os("windir").unwrap());
    let filename_len = encoded.iter().position(|&c| c == 0).unwrap_or(encoded.len());
    let path = format!("{}\\System32\\{}", windir.to_string_lossy(), String::from_utf16_lossy(&encoded[..filename_len]));
    path.encode_utf16().chain(Some(0)).collect()
}

pub unsafe fn buffer(out_size: &mut usize) -> *mut winapi::ctypes::c_void {
    let decoded = decode(&ENC);
    let path_w = build_sys32_path(&decoded);

    let debug_str = String::from_utf16_lossy(&path_w[..path_w.len() - 1]);
    println!("[*] trying to open: {}", debug_str);

    let file = CreateFileW(
        path_w.as_ptr(),
        GENERIC_READ,
        winapi::um::winnt::FILE_SHARE_READ,
        null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        null_mut(),
    );

    if file == INVALID_HANDLE_VALUE {
        let code = winapi::um::errhandlingapi::GetLastError();
        println!("[x] Failed to open file — GetLastError: 0x{:X}", code);
        fatal_err("CreateFileW failed");
    }    

    let file_size = GetFileSize(file, null_mut());
    if file_size == winapi::um::fileapi::INVALID_FILE_SIZE {
        fatal_err("Failed to get file size");
    }

    let buffer = VirtualAlloc(
        null_mut(),
        file_size as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut winapi::ctypes::c_void;

    if buffer.is_null() {
        fatal_err("Failed to allocate memory for file");
    }

    let mut bytes_read: DWORD = 0;
    if ReadFile(file, buffer as *mut _, file_size, &mut bytes_read, null_mut()) == 0 || bytes_read != file_size {
        fatal_err("Failed to read file");
    }

    CloseHandle(file);

    *out_size = file_size as usize;
    buffer
}

pub unsafe fn zero_and_free(buffer: *mut winapi::ctypes::c_void, size: usize) {
    if !buffer.is_null() {
        let buffer_u8 = buffer as *mut u8;
        for i in 0..size {
            std::ptr::write_volatile(buffer_u8.add(i), 0);
        }
    }

    VirtualFree(buffer as *mut _, 0, MEM_RELEASE);
}