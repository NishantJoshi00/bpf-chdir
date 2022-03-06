#![no_std]
#![no_main]

use cty::*;
use probes::tap::{FdPid, Path, MAPSIZE};
use redbpf_probes::kprobe::prelude::*;

use core::mem::{self, MaybeUninit};

program!(0xFFFFFFFE, "GPL");

#[map]
static mut CHDIR_MAP: PerfMap<Path> = PerfMap::with_max_entries(MAPSIZE);

#[map]
static mut FCHDIR_MAP: PerfMap<FdPid> = PerfMap::with_max_entries(MAPSIZE);

#[kprobe]
fn chdir_entry(regs: Registers) {
    let ctx = regs.ctx;
    let mut uninit = MaybeUninit::<pt_regs>::uninit();
    let rv = unsafe {
        bpf_probe_read_kernel(
            uninit.as_mut_ptr() as *mut _,
            mem::size_of::<pt_regs>() as u32,
            regs.parm1() as *const u64 as *const c_void,
        )
    };

    if rv < 0 {
        bpf_trace_printk(b"error on bpf_probe_read_kernel\0");
        return;
    }

    let regs = Registers::from(uninit.as_mut_ptr() as *mut c_void);

    let mut path = Path::default();

    let len = unsafe {
        bpf_probe_read_user_str(
            path.path.as_mut_ptr() as *mut c_void,
            path.path.len() as u32,
            regs.parm1() as *const u64 as *const c_void,
        )
    };

    if len <= 0 {
        bpf_trace_printk(b"Error in bpf_probe_read_str\0");
        return;
    }

    unsafe { CHDIR_MAP.insert(ctx, &path) };
}

#[kprobe]
fn fchdir_entry(regs: Registers) {
    let ctx = regs.ctx;
    let mut uninit = MaybeUninit::<pt_regs>::uninit();

    let rv = unsafe {
        bpf_probe_read_kernel(
            uninit.as_mut_ptr() as *mut _,
            mem::size_of::<pt_regs>() as u32,
            regs.parm1() as *const u64 as *const c_void,
        )
    };

    if rv < 0 {
        bpf_trace_printk(b"error in bpf_probe_read_kernel\0");
        return;
    }

    let regs = Registers::from(uninit.as_mut_ptr() as *mut c_void);

    let fd = FdPid {
        fd: regs.parm1(),
        pid: (bpf_get_current_pid_tgid() >> 32) as u64,
    };
    unsafe {
        FCHDIR_MAP.insert(ctx, &fd);
    }
}
