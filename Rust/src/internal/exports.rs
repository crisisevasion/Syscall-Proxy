use crate::internal::err::fatal_err;

use std::ffi::CStr;
use std::sync::OnceLock;
use std::os::raw::c_char;
use std::collections::HashMap;
use std::ptr::{null_mut, null};

use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
    IMAGE_DATA_DIRECTORY, IMAGE_EXPORT_DIRECTORY,
};

use winapi::shared::minwindef::{DWORD, WORD};
use winapi::ctypes::c_void;

pub static SYSCALL_TABLE: OnceLock<HashMap<String, u32>> = OnceLock::new();

pub unsafe fn get_export_address(module_base: *mut c_void, function_name: &str) -> *mut u8 {
    if module_base.is_null() {
        return null_mut();
    }

    let dos = module_base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return null_mut();
    }

    let nt = (module_base as *const u8).add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return null_mut();
    }

    let export_data: IMAGE_DATA_DIRECTORY = (*nt).OptionalHeader.DataDirectory[0];
    if export_data.VirtualAddress == 0 {
        return null_mut();
    }

    let base = module_base as *const u8;
    let export_dir = base.add(export_data.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names = base.add((*export_dir).AddressOfNames as usize) as *const DWORD;
    let ordinals = base.add((*export_dir).AddressOfNameOrdinals as usize) as *const WORD;
    let functions = base.add((*export_dir).AddressOfFunctions as usize) as *const DWORD;

    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.add(i as usize) as usize;
        let name_ptr = base.add(name_rva) as *const c_char;

        let Ok(name_str) = CStr::from_ptr(name_ptr).to_str() else { continue };

        if name_str.eq_ignore_ascii_case(function_name) {
            let ordinal = *ordinals.add(i as usize) as usize;
            let func_rva = *functions.add(ordinal) as usize;
            return base.add(func_rva) as *mut u8;
        }
    }

    null_mut()
}

pub unsafe fn extract_ssn(mapped_base: *mut c_void, mapped_size: usize) -> HashMap<String, u32> {
    let mut table = HashMap::new();
    let base = mapped_base as *const u8;

    let dos = mapped_base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        fatal_err("invalid DOS header");
    }

    let nt = base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        fatal_err("invalid NT header");
    }

    let export_data = (*nt).OptionalHeader.DataDirectory[0];
    if export_data.VirtualAddress == 0 {
        fatal_err("no export directory");
    }

    let export_dir = base.add(export_data.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names = base.add((*export_dir).AddressOfNames as usize) as *const DWORD;
    let ordinals = base.add((*export_dir).AddressOfNameOrdinals as usize) as *const WORD;
    let functions = base.add((*export_dir).AddressOfFunctions as usize) as *const DWORD;

    let num_names = (*export_dir).NumberOfNames as usize;
    println!("[*] parsing {} export names", num_names);

    for i in 0..num_names {
        let name_rva = *names.add(i) as usize;
        if name_rva >= mapped_size {
            println!("[-] name_rva OOB: {:#x}", name_rva);
            continue;
        }

        let name_ptr = base.add(name_rva) as *const u8;

        // validate null terminator within bounds
        let mut max_len = 0usize;
        while max_len < 256 {
            let p = name_ptr.add(max_len);
            if (p as usize) >= (base as usize + mapped_size) {
                break;
            }
            if *p == 0 {
                break;
            }
            max_len += 1;
        }

        if max_len == 256 || (name_ptr.add(max_len) as usize) >= base as usize + mapped_size {
            println!("[-] export name unterminated or OOB");
            continue;
        }

        let Ok(name_str) = CStr::from_ptr(name_ptr as *const c_char).to_str() else {
            println!("[-] invalid UTF-8 in export name");
            continue;
        };

        if !name_str.starts_with("Nt") {
            continue;
        }

        let ordinal = *ordinals.add(i) as usize;
        let func_rva = *functions.add(ordinal) as usize;

        if func_rva + 8 > mapped_size {
            println!("[-] stub OOB for {}", name_str);
            continue;
        }

        let stub = base.add(func_rva);

        if *stub != 0x4C || *stub.add(1) != 0x8B || *stub.add(2) != 0xD1 || *stub.add(3) != 0xB8 {
            continue;
        }

        let ssn = *(stub.add(4) as *const u32);
        println!("[+] {} => SSN: {:#x}", name_str, ssn);

        table.insert(name_str.to_owned(), ssn);
    }

    println!("[*] done. extracted {} entries", table.len());
    table
}