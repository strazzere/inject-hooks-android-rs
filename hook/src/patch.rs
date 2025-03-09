
use crate::logd;

use std::ptr;
use std::slice;
use std::os::raw::c_void;
use libc::{mprotect, PROT_EXEC, PROT_READ, PROT_WRITE};

// TODO : Lots of this should be gated behind arm only compilation

#[inline(always)]
unsafe fn clear_cache(begin: *mut u8, end: *mut u8) {
    core::arch::asm!(
        "mov r0, {0}",
        "mov r1, {1}",
        "blx {2}",
        in(reg) begin,
        in(reg) end,
        in(reg) 0xffff0fa0u32 as *const c_void, // __clear_cache syscall
        options(nostack)
    );
}

pub unsafe fn patch_thumb_hook(target: *mut u8, hook: *const u8) {
  let page_size = 4096;
  let page = target as usize & !(page_size - 1);

  let addr = (hook as usize | 1) as u32;

  libc::mprotect(page as *mut c_void, page_size, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);

  // Thumb patch: ldr r12, [pc, #4] ; bx r12 ; .word hook_addr
  let patch: [u8; 12] = [
    0xdf, 0xf8, 0x04, 0xc0, // ldr r12, [pc, #4]
    0x60, 0x47,             // bx r12
    0x00, 0x00,             // optional padding to align .word on 4-byte boundary (NOP in Thumb)
    (addr & 0xff) as u8,
    ((addr >> 8) & 0xff) as u8,
    ((addr >> 16) & 0xff) as u8,
    ((addr >> 24) & 0xff) as u8,
];

  ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());

  clear_cache(target, target.add(patch.len()));

  libc::mprotect(page as *mut c_void, page_size, libc::PROT_READ | libc::PROT_EXEC);
}

pub unsafe fn make_thumb_trampoline(original: *const u8) -> *const u8 {
    logd!("[*] Creating trampoline for address: {:#x}", original as usize);
    logd!("[*] First 16 bytes at original ({:#x}): {:?}", original as usize, slice::from_raw_parts(original, 16));

    let real_ptr = (original as usize & !1) as *const u8;
    logd!("[*] Stripped Thumb bit, real function pointer: {:#x}", real_ptr as usize);

    let trampoline = libc::mmap(
        ptr::null_mut(),
        0x1000,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut u8;

    if trampoline.is_null() {
        logd!("[-] Failed to allocate trampoline memory");
        return ptr::null();
    }

    logd!("[*] Trampoline address: {:#x} (aligned? {})", trampoline as usize, trampoline as usize % 2 == 0);

    // Read as u16 to check if instructions are 16-bit or 32-bit
    let mut offset = 0;
    while offset < 8 {
        let instr = *(real_ptr.add(offset) as *const u16);
        let is_32bit = is_32bit_thumb(instr);
        logd!("[*] Instruction at offset {:#x}: {:#06x} is_32bit={}", offset, instr, is_32bit);
        let size = if is_32bit { 4 } else { 2 };

        if offset + size > 8 {
            logd!("[-] Cannot safely copy past 8 bytes without disassembler");
            break;
        }

        ptr::copy_nonoverlapping(real_ptr.add(offset), trampoline.add(offset), size);
        offset += size;
    }

    logd!("[*] Copied {} bytes into trampoline", offset);

    // Set up jump back to original + offset
    let return_addr = (real_ptr as usize + offset) | 1;
    let return_addr_bytes = (return_addr as u32).to_le_bytes();

    let patch: [u8; 12] = [
        0xdf, 0xf8, 0x04, 0xc0, // ldr r12, [pc, #4]
        0x60, 0x47,             // bx r12
        0x00, 0x00,             // padding
        return_addr_bytes[0],
        return_addr_bytes[1],
        return_addr_bytes[2],
        return_addr_bytes[3],
    ];

    ptr::copy_nonoverlapping(patch.as_ptr(), trampoline.add(offset), patch.len());

    let final_len = offset + patch.len();
    logd!("[*] Final trampoline contents: {:?}", std::slice::from_raw_parts(trampoline, final_len));


    logd!("[*] Patch for trampoline return: {:?}", &patch);
    logd!("[*] Trampoline set up at {:#x}, returning to {:#x}", trampoline as usize, return_addr);

    clear_cache(trampoline, trampoline.add(offset + patch.len()));
    trampoline.add(1) as *const u8 // Set Thumb bit
}

/// Returns true if the instruction is the first half of a 32-bit Thumb instruction.
fn is_32bit_thumb(instr: u16) -> bool {
  match instr >> 11 {
      0b11101 | // BL, BLX, conditional branches
      0b11110 | // Many 32-bit instructions
      0b11111 => true, // Other 32-bit instructions
      _ => false,
  }
}

// This is safer than utilizing the trampolines
pub unsafe fn patch_got_entry(addr: *mut *const c_void, replacement: *const c_void) -> *const c_void {
    let page_size = 4096;
    let page = (addr as usize) & !(page_size - 1);

    mprotect(page as *mut c_void, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    let original = *addr;
    *addr = (replacement as usize | 1) as *const c_void;

    mprotect(page as *mut c_void, page_size, PROT_READ | PROT_EXEC);

    original
}

