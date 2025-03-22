use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use lazy_static::lazy_static;

use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, MEM_COMMIT, MEM_RESERVE};

use crate::internal::crypto::lea::{lea_encrypt_block, lea_decrypt_block};
use crate::internal::sentry::{SyscallState, ab_callback};

pub const STUB_SIZE: usize = 32;
const NUM_STUBS: usize = 32;
const SYSCALL_OFFSET: usize = 8;

#[repr(C)]
pub struct StubSlot {
    pub addr: *mut u8,
    pub active: AtomicBool,
    pub encrypted: AtomicBool,
    pub state: Mutex<Option<SyscallState>>,
}

unsafe impl Send for StubSlot {}
unsafe impl Sync for StubSlot {}

pub struct StubPool {
    pub slots: [StubSlot; NUM_STUBS],
}

unsafe impl Send for StubPool {}
unsafe impl Sync for StubPool {}

lazy_static! {
    pub static ref G_STUB_POOL: Mutex<StubPool> = Mutex::new(StubPool::init());
}

impl StubPool {
    pub fn init() -> Self {
        let slots: [StubSlot; NUM_STUBS] = std::array::from_fn(|_| {
            let stub = Self::alloc_stub();
            unsafe {
                lea_encrypt_block(stub, STUB_SIZE);
                VirtualProtect(stub as _, STUB_SIZE, PAGE_NOACCESS, &mut 0);
            }
            StubSlot {
                addr: stub,
                active: AtomicBool::new(false),
                encrypted: AtomicBool::new(true),
                state: Mutex::new(None),
            }
        });
        StubPool { slots }
    }

    fn alloc_stub() -> *mut u8 {
        let mem = unsafe {
            VirtualAlloc(null_mut(), STUB_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        } as *mut u8;
        if mem.is_null() {
            panic!("failed to allocate stub");
        }

        let prologue: [u8; STUB_SIZE] = [
            0x4C, 0x8B, 0xD1,
            0xB8, 0x00, 0x00, 0x00, 0x00,
            0xCC, 0xC3,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        ];

        unsafe {
            std::ptr::copy_nonoverlapping(prologue.as_ptr(), mem, STUB_SIZE);
        }

        mem
    }

    pub fn acquire(&mut self) -> Option<*mut u8> {
        for slot in self.slots.iter_mut() {
            if !slot.active.swap(true, Ordering::SeqCst) {
                unsafe {
                    VirtualProtect(slot.addr as _, STUB_SIZE, PAGE_EXECUTE_READWRITE, &mut 0);
                    if slot.encrypted.swap(false, Ordering::SeqCst) {
                        lea_decrypt_block(slot.addr, STUB_SIZE);
                    }
                }
                *slot.state.lock().unwrap() = Some(SyscallState::capture());
                return Some(slot.addr);
            }
        }
        None
    }

    pub fn release(&mut self, addr: *mut u8) {
        for slot in self.slots.iter_mut() {
            if slot.addr == addr {
                if let Some(state) = slot.state.lock().unwrap().take() {
                    unsafe { ab_callback(&state); }
                }
                unsafe {
                    addr.add(SYSCALL_OFFSET).write(0xCC);
                    lea_encrypt_block(addr, STUB_SIZE);
                    VirtualProtect(addr as _, STUB_SIZE, PAGE_NOACCESS, &mut 0);
                }
                
                slot.encrypted.store(true, Ordering::SeqCst);
                slot.active.store(false, Ordering::SeqCst);
            }
        }
    }
}