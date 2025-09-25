use libc::{c_void, pid_t};
use std::io::{Error, Result};
use std::mem::{size_of, zeroed};
use std::ptr;

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PtRegs {
    // Matches Linux user_pt_regs: x0..x30, sp, pc, pstate
    pub regs: [u64; 31], // x0..x30
    pub sp: u64,         // stack pointer
    pub pc: u64,         // program counter
    pub pstate: u64,     // processor state
}

#[cfg(target_arch = "arm")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PtRegs {
    // Matches struct pt_regs armv7
    pub uregs: [u32; 18],
}

pub fn ptrace_attach(pid: pid_t) -> Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) } < 0 {
        return Err(Error::last_os_error());
    }
    let _ = waitpid(Pid::from_raw(pid), None);
    #[cfg(debug_assertions)]
    eprintln!("[ptrace] Attached to {}", pid);
    Ok(())
}

pub fn ptrace_detach(pid: pid_t) -> Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) } < 0 {
        return Err(Error::last_os_error());
    }
    #[cfg(debug_assertions)]
    eprintln!("[ptrace] Detached from {}", pid);
    Ok(())
}

pub fn ptrace_peek_word(pid: pid_t, addr: *mut c_void) -> usize {
    // Deliberately ignore errno weirdness (-1 vs error) to avoid errno access on android
    unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr, ptr::null_mut::<c_void>()) as usize }
}

fn ptrace_poke_word(pid: pid_t, addr: *mut c_void, data: usize) -> Result<()> {
    let ret = unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid, addr, data) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

pub fn ptrace_write(pid: pid_t, addr: *mut u8, data: &[u8]) -> Result<()> {
    let word_size = size_of::<usize>();
    let mut offset = 0;

    // Full words
    while offset + word_size <= data.len() {
        let word = usize::from_ne_bytes(data[offset..offset + word_size].try_into().unwrap());
        ptrace_poke_word(pid, unsafe { addr.add(offset) } as *mut c_void, word)?;
        offset += word_size;
    }

    // Leftovers
    if offset < data.len() {
        let tail_addr = unsafe { addr.add(offset) } as *mut c_void;
        let mut word = ptrace_peek_word(pid, tail_addr);
        let ptr_u8 = &mut word as *mut _ as *mut u8;
        let tail_len = data.len() - offset;
        for i in 0..tail_len {
            unsafe { *ptr_u8.add(i) = data[offset + i]; }
        }
        ptrace_poke_word(pid, tail_addr, word)?;
    }

    #[cfg(debug_assertions)]
    eprintln!("[ptrace] Wrote {} bytes to {:p}", data.len(), addr);
    Ok(())
}

fn wait_until_stopped(pid: pid_t) -> Result<WaitStatus> {
    println!("[ptrace] wait_until_stopped: waiting for pid {}", pid);
    loop {
        match waitpid(Pid::from_raw(pid), None) {
            Ok(WaitStatus::Stopped(_, _sig)) => {
                println!("[ptrace] wait_until_stopped: process stopped with signal {:?}", _sig);
                return Ok(WaitStatus::Stopped(Pid::from_raw(pid), _sig));
            }
            Ok(WaitStatus::Exited(_, code)) => {
                println!("[ptrace] wait_until_stopped: process exited with code {}", code);
                return Err(Error::new(std::io::ErrorKind::Other, format!("tracee exited with {}", code)));
            }
            Ok(WaitStatus::Signaled(_, sig, _core)) => {
                println!("[ptrace] wait_until_stopped: process signaled with {:?}", sig);
                return Err(Error::new(std::io::ErrorKind::Other, format!("tracee signaled: {:?}", sig)));
            }
            Ok(status) => {
                println!("[ptrace] wait_until_stopped: other status: {:?}, continuing to wait", status);
                continue;
            }
            Err(e) => {
                println!("[ptrace] wait_until_stopped: error waiting for process: {:?}", e);
                return Err(Error::from(e));
            }
        }
    }
}

// aarch64 mode only
#[cfg(target_arch = "aarch64")]
mod arch64 {
    use super::*;
    use libc::iovec;

    const NT_PRSTATUS: i32 = 1;

    pub fn get_regs(pid: pid_t, regs: &mut PtRegs) -> Result<()> {
        let mut iov = iovec { iov_base: regs as *mut _ as *mut c_void, iov_len: std::mem::size_of::<PtRegs>() };
        let ret = unsafe { libc::ptrace(libc::PTRACE_GETREGSET, pid, NT_PRSTATUS as *mut c_void, &mut iov as *mut _ as *mut c_void) };
        if ret < 0 { return Err(Error::last_os_error()); }
        Ok(())
    }

    pub fn set_regs(pid: pid_t, regs: &PtRegs) -> Result<()> {
        let mut iov = iovec { iov_base: regs as *const _ as *mut c_void, iov_len: std::mem::size_of::<PtRegs>() };
        let ret = unsafe { libc::ptrace(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS as *mut c_void, &mut iov as *mut _ as *mut c_void) };
        if ret < 0 { return Err(Error::last_os_error()); }
        Ok(())
    }

    #[inline]
    fn a64_call_stub() -> [u8; 8] {
        // blr x17 ; brk #0
        let blr_x17: u32 = 0xD63F_0220;
        let brk0:    u32 = 0xD420_0000;
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&blr_x17.to_le_bytes());
        b[4..].copy_from_slice(&brk0.to_le_bytes());
        b
    }

    #[inline]
    fn a64_syscall_stub() -> [u8; 8] {
        // svc #0 ; brk #0
        let svc0: u32 = 0xD400_0001;
        let brk0: u32 = 0xD420_0000;
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&svc0.to_le_bytes());
        b[4..].copy_from_slice(&brk0.to_le_bytes());
        b
    }

    // Simple page for tramp
    static mut STUB_PAGE: u64 = 0;

    // Set LR (x30) = 0 so when the callee RETs it segfaults at 0 so we can catch halt
    // Read x0, restore regs then continue
    fn call_lib_once_with_lr_trap(pid: pid_t, func_addr: u64, args: &[u64]) -> Result<u64> {
        let mut regs: PtRegs = unsafe { zeroed() };
        get_regs(pid, &mut regs)?;
        let backup = regs;

        for (i, a) in args.iter().take(8).enumerate() { regs.regs[i] = *a; }
        // spill extras with 16B SP alignment
        spill_extra_args_aapcs64(pid, &mut regs, args)?;

        // LR = 0 -> trap on return
        regs.regs[30] = 0;
        // jump directly into libc function
        regs.pc = func_addr;

        set_regs(pid, &regs)?;
        let r = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
        if r < 0 { set_regs(pid, &backup).ok(); return Err(Error::last_os_error()); }

        // Wait for SIGSEGV
        super::wait_until_stopped(pid)?;
        get_regs(pid, &mut regs)?;
        let ret = regs.regs[0];

        // Restore regs so we don't re-execute anything
        set_regs(pid, &backup)?;
        Ok(ret)
    }

    // Ensure we have a trampoline page; if not, get one
    // We resolve and call libc::mmap once using the LR-trap trick, then place our stubs there
    fn ensure_stub_page(pid: pid_t, libc_mmap_addr: u64) -> Result<u64> {
        unsafe {
            if STUB_PAGE != 0 { return Ok(STUB_PAGE); }
        }

        // mmap(NULL, 0x1000, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0) via libc mmap
        let page_sz = 0x1000u64;
        let prot    = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
        let flags   = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
        let fd      = !0u64;
        let off     = 0u64;

        let addr = call_lib_once_with_lr_trap(pid, libc_mmap_addr, &[0, page_sz, prot, flags, fd, off])?;
        if addr == 0 || (addr as i64) < 0 {
            return Err(Error::new(std::io::ErrorKind::Other, format!("bootstrap mmap failed: 0x{:x}", addr)));
        }

        // Write both stubs into the page: put call stub at +0, syscall stub at +8 (or vice versa).
        let call_stub = a64_call_stub();
        super::ptrace_write(pid, addr as *mut u8, &call_stub)?;
        let sysc_stub = a64_syscall_stub();
        super::ptrace_write(pid, (addr + 8) as *mut u8, &sysc_stub)?;

        unsafe { STUB_PAGE = addr; }
        Ok(addr)
    }

    pub(super) fn spill_extra_args_aapcs64(pid: pid_t, regs: &mut PtRegs, args: &[u64]) -> Result<()> {
        if args.len() <= 8 { return Ok(()); }
        let extra = &args[8..];
        let bytes = extra.len() * 8;
        let aligned = (bytes + 15) & !15;
        let new_sp = regs.sp.wrapping_sub(aligned as u64);

        let mut raw = Vec::with_capacity(aligned);
        for a in extra { raw.extend_from_slice(&a.to_ne_bytes()); }
        while raw.len() % 16 != 0 { raw.push(0); }

        super::ptrace_write(pid, new_sp as *mut u8, &raw)?;
        regs.sp = new_sp;
        Ok(())
    }

    // Uses the call-stub if available; on first use it bootstraps the stub page by
    // call libc::mmap once via LR-trap. Pass the remote address of mmap as `libc_mmap_addr`
    pub fn call_remote_function(pid: pid_t, func_addr: u64, args: &[u64], libc_mmap_addr: u64) -> Result<u64> {
        // Ensure we have a stub page; if not, this will use LR-trap to get one via libc::mmap
        let page = ensure_stub_page(pid, libc_mmap_addr)?;
        let call = page; // call stub sits at +0

        // Normal call via `blr x17; brk #0`
        let mut regs: PtRegs = unsafe { zeroed() };
        get_regs(pid, &mut regs)?;
        let backup = regs;

        for (i, a) in args.iter().take(8).enumerate() { regs.regs[i] = *a; }
        spill_extra_args_aapcs64(pid, &mut regs, args)?;

         // x17 = target
        regs.regs[17] = func_addr;
        regs.pc = call;

        set_regs(pid, &regs)?;
        let r = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
        if r < 0 {
            set_regs(pid, &backup).ok();
            return Err(Error::last_os_error());
        }

        super::wait_until_stopped(pid)?;
        get_regs(pid, &mut regs)?;
        let ret = regs.regs[0];

        set_regs(pid, &backup)?;
        Ok(ret)
    }
}

#[cfg(target_arch = "aarch64")]
pub use arch64::call_remote_function;

// armv7/32bit
#[cfg(target_arch = "arm")]
mod arch32 {
    use super::*;

    fn get_regs(pid: pid_t, regs: &mut PtRegs) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(libc::PTRACE_GETREGS, pid, ptr::null_mut::<c_void>(), regs as *mut _ as *mut c_void)
        };
        if ret < 0 { return Err(Error::last_os_error()); }
        Ok(())
    }

    fn set_regs(pid: pid_t, regs: &PtRegs) -> Result<()> {
        let ret = unsafe {
            libc::ptrace(libc::PTRACE_SETREGS, pid, ptr::null_mut::<c_void>(), regs as *const _ as *const c_void)
        };
        if ret < 0 { return Err(Error::last_os_error()); }
        Ok(())
    }

    pub fn call_remote_function(pid: pid_t, func_addr: u64, args: &[u64], _libc_mmap_addr: u64) -> Result<u64> {
        let mut regs: PtRegs = unsafe { zeroed() };
        get_regs(pid, &mut regs)?;
        let backup = regs;

        for i in 0..args.len().min(4) { regs.uregs[i] = args[i] as u32; }

        if args.len() > 4 {
            let extra = &args[4..];
            let sp = (regs.uregs[13] as usize).wrapping_sub(extra.len() * size_of::<u32>());
            let mut raw = Vec::with_capacity(extra.len() * 4);
            for a in extra { raw.extend_from_slice(&(*a as u32).to_ne_bytes()); }
            super::ptrace_write(pid, sp as *mut u8, &raw)?;
            regs.uregs[13] = sp as u32;
        }

        // LR
        regs.uregs[14] = 0;
        regs.uregs[15] = (func_addr & !1) as u32;
        if (func_addr & 1) != 0 { regs.uregs[16] |= 0x20; } else { regs.uregs[16] &= !0x20; }

        set_regs(pid, &regs)?;
        let r = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, ptr::null_mut::<c_void>(), ptr::null_mut::<c_void>()) };
        if r < 0 { set_regs(pid, &backup).ok(); return Err(Error::last_os_error()); }

        let _ = super::wait_until_stopped(pid)?;

        get_regs(pid, &mut regs)?;
        let ret = regs.uregs[0] as u64;

        set_regs(pid, &backup)?;

    #[cfg(debug_assertions)]
        eprintln!("[ptrace:arm] call_remote_function 0x{func_addr:x} -> 0x{ret:x}");

        Ok(ret)
    }
}

#[cfg(target_arch = "arm")]
pub use arch32::call_remote_function;