use libc::{c_void, pid_t, PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_CONT, PTRACE_POKEDATA, PTRACE_PEEKDATA};
use std::io::{Result, Error};
use std::mem::{size_of, zeroed};
use std::ptr;

use nix::sys::wait::waitpid;
use nix::unistd::Pid;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PtRegs {
    pub uregs: [u32; 18],
}

pub fn ptrace_attach(pid: pid_t) -> Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) } < 0 {
        return Err(Error::last_os_error());
    }
    let _ = waitpid(Pid::from_raw(pid), None);
    #[cfg(debug_assertions)]
    println!("Attached to process {}", pid);
    Ok(())
}

pub fn ptrace_detach(pid: pid_t) -> Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) } < 0 {
        return Err(Error::last_os_error());
    }
    #[cfg(debug_assertions)]
    println!("Detached from process {}", pid);
    Ok(())
}

pub fn ptrace_write(pid: pid_t, addr: *mut u8, data: &[u8]) {
    let word_size = size_of::<usize>();
    let mut offset = 0;

    while offset + word_size <= data.len() {
        let word = usize::from_ne_bytes(data[offset..offset + word_size].try_into().unwrap());
        unsafe {
            libc::ptrace(PTRACE_POKEDATA, pid, addr.add(offset), word);
        }
        offset += word_size;
    }

    if offset < data.len() {
        let mut val = unsafe {
            libc::ptrace(PTRACE_PEEKDATA, pid, addr.add(offset), ptr::null_mut::<c_void>())
        };
        let val_ptr = &mut val as *mut _ as *mut u8;
        for i in 0..(data.len() - offset) {
            unsafe {
                *val_ptr.add(i) = data[offset + i];
            }
        }
        unsafe {
            libc::ptrace(PTRACE_POKEDATA, pid, addr.add(offset), val);
        }
    }

    #[cfg(debug_assertions)]
    println!("Wrote {} bytes to {:p}", data.len(), addr);
}

pub fn call_remote_function(
    pid: pid_t,
    func_addr: u64,
    args: &[u64]
) -> Result<u64> {
    let mut regs: PtRegs = unsafe { zeroed() };
    let backup_regs: PtRegs;

    unsafe {
        libc::ptrace(PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), &mut regs as *mut _ as *mut c_void);
        backup_regs = regs;
    }

    for i in 0..args.len().min(4) {
        regs.uregs[i] = args[i] as u32;
    }

    if args.len() > 4 {
        let extra = &args[4..];
        let sp = (regs.uregs[13] as usize) - (extra.len() * size_of::<u32>());
        let mut raw = vec![];
        for arg in extra {
            raw.extend_from_slice(&(*arg as u32).to_ne_bytes());
        }
        ptrace_write(pid, sp as *mut u8, &raw);
        regs.uregs[13] = sp as u32;
    }

    regs.uregs[14] = 0;
    regs.uregs[15] = (func_addr & !1) as u32;
    if func_addr & 1 != 0 {
        regs.uregs[16] |= 0x20;
    } else {
        regs.uregs[16] &= !0x20;
    }

    unsafe {
        libc::ptrace(PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), &regs as *const _ as *const c_void);
        libc::ptrace(PTRACE_CONT, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>());
    }

    let _ = waitpid(Pid::from_raw(pid), None);

    unsafe {
        libc::ptrace(PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), &mut regs as *mut _ as *mut c_void);
        libc::ptrace(PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), &backup_regs as *const _ as *const c_void);
    }

    #[cfg(debug_assertions)]
    println!("Call remote 0x{:x} returned 0x{:x}", func_addr, regs.uregs[0]);

    Ok(regs.uregs[0] as u64)
}