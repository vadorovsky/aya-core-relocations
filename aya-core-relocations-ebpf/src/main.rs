#![no_std]
#![no_main]

use aya_ebpf::{
    Global,
    cty::{c_int, c_uint},
    helpers::bpf_probe_read_kernel,
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<i32> = Global::new(0);

#[repr(transparent)]
struct Relocatable(core::marker::PhantomData<()>);

#[repr(C)]
struct task_struct {
    pid: i32,
    tgid: i32,

    _relocatable: Relocatable,
}

#[kprobe]
pub fn kprobe_try_to_wake_up(ctx: ProbeContext) -> u32 {
    let _ = try_kprobe_try_to_wake_up(ctx);
    0
}

fn try_kprobe_try_to_wake_up(ctx: ProbeContext) -> Result<u32, i32> {
    let task: *const task_struct = ctx.arg(0).ok_or(-1)?;
    let pid = unsafe { bpf_probe_read_kernel(&(*task).pid)? };
    let tgid = unsafe { bpf_probe_read_kernel(&(*task).tgid)? };
    if tgid != TARGET_TGID.load() {
        return Ok(0);
    }

    let state: c_uint = ctx.arg(1).ok_or(-1)?;
    let wake_flags: c_int = ctx.arg(2).ok_or(-1)?;

    info!(
        &ctx,
        "`try_to_wake_up`: pid: {}, tgid: {}, state: {}, wake_flags: {}",
        pid,
        tgid,
        state,
        wake_flags
    );

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
