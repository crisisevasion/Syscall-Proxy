use core::arch::x86_64::*;
use core::arch::x86_64::{__cpuid, _rdtsc};

const ROUNDS: usize = 24;

pub fn key() -> [u8; 16] {

    let cpu = unsafe { __cpuid(0) };
    let tsc = unsafe { _rdtsc() };
    let mut key = [0u8; 16];

    key[0..4].copy_from_slice(&cpu.eax.to_le_bytes());
    key[4..8].copy_from_slice(&cpu.ebx.to_le_bytes());
    key[8..12].copy_from_slice(&(tsc as u32).to_le_bytes());
    key[12..16].copy_from_slice(&((tsc >> 32) as u32).to_le_bytes());

    key
}

pub struct LEA128 {
    round_keys: [u32; ROUNDS * 6],
}

impl LEA128 {

    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [0u32; ROUNDS * 6];
        let k = [
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
        ];

        let delta: [u32; ROUNDS] = [
            0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a,
            0xd8ec4f6d, 0x0a5c91b5, 0xac50c01f, 0xc2cfcdf1, 0xa526c7f0, 0x05a79f6b,
            0x8d58c2d3, 0x0c98bf8c, 0x2f7b012f, 0x5cb81a71, 0xf3e65c1e, 0x3b24c7ca,
            0x8e83fed3, 0xcfd3c8ab, 0x23a5f89c, 0x35581a63, 0x965d5f2d, 0x118db980,
        ];

        for i in 0..ROUNDS {
            let d = delta[i].rotate_left(i as u32);
            rk[i * 6 + 0] = k[0].rotate_left(1).wrapping_add(d);
            rk[i * 6 + 1] = k[1].rotate_left(3).wrapping_add(d);
            rk[i * 6 + 2] = k[2].rotate_left(6).wrapping_add(d);
            rk[i * 6 + 3] = k[1].rotate_left(11).wrapping_add(d);
            rk[i * 6 + 4] = k[2].rotate_left(13).wrapping_add(d);
            rk[i * 6 + 5] = k[3].rotate_left(17).wrapping_add(d);
        }

        Self { round_keys: rk }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut x = [
            u32::from_le_bytes(block[0..4].try_into().unwrap()),
            u32::from_le_bytes(block[4..8].try_into().unwrap()),
            u32::from_le_bytes(block[8..12].try_into().unwrap()),
            u32::from_le_bytes(block[12..16].try_into().unwrap()),
        ];

        for r in 0..ROUNDS {
            let k = &self.round_keys[r * 6..];
            let t0 = x[0].rotate_left(9) ^ x[1].wrapping_add(k[0]);
            let t1 = x[1].rotate_right(5) ^ x[2].wrapping_add(k[1]);
            let t2 = x[2].rotate_right(3) ^ x[3].wrapping_add(k[2]);
            let t3 = x[3].rotate_left(9) ^ x[0].wrapping_add(k[3]);
            x = [t0, t1, t2, t3];
        }

        block[0..4].copy_from_slice(&x[0].to_le_bytes());
        block[4..8].copy_from_slice(&x[1].to_le_bytes());
        block[8..12].copy_from_slice(&x[2].to_le_bytes());
        block[12..16].copy_from_slice(&x[3].to_le_bytes());
    }

    pub fn decrypt_block(&self, block: &mut [u8; 16]) {

        let mut x = [
            u32::from_le_bytes(block[0..4].try_into().unwrap()),
            u32::from_le_bytes(block[4..8].try_into().unwrap()),
            u32::from_le_bytes(block[8..12].try_into().unwrap()),
            u32::from_le_bytes(block[12..16].try_into().unwrap()),
        ];

        for r in (0..ROUNDS).rev() {
            let k = &self.round_keys[r * 6..];
            let t3 = x[3].wrapping_sub(x[0].rotate_left(9)) ^ k[3];
            let t2 = x[2].rotate_left(3) ^ x[3].wrapping_add(k[2]);
            let t1 = x[1].rotate_left(5) ^ x[2].wrapping_add(k[1]);
            let t0 = x[0].wrapping_sub(x[1].wrapping_add(k[0])).rotate_right(9);
            x = [t0, t1, t2, t3];
        }

        block[0..4].copy_from_slice(&x[0].to_le_bytes());
        block[4..8].copy_from_slice(&x[1].to_le_bytes());
        block[8..12].copy_from_slice(&x[2].to_le_bytes());
        block[12..16].copy_from_slice(&x[3].to_le_bytes());
    }
}

pub fn lea_encrypt_block(ptr: *mut u8, len: usize) {
    let key = key();
    let cipher = LEA128::new(&key);
    let mut i = 0;
    while i + 16 <= len {
        unsafe {
            let block = std::slice::from_raw_parts_mut(ptr.add(i), 16).try_into().unwrap();
            cipher.encrypt_block(block);
        }

        i += 16;
    }
}

pub fn lea_decrypt_block(ptr: *mut u8, len: usize) {
    let key = key();
    let cipher = LEA128::new(&key);
    let mut i = 0;
    while i + 16 <= len {
        unsafe {
            let block = std::slice::from_raw_parts_mut(ptr.add(i), 16).try_into().unwrap();
            cipher.decrypt_block(block);
        }

        i += 16;
    }
}