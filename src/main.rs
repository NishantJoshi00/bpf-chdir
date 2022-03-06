use futures::StreamExt;
use std::{error::Error, ffi::CStr, ptr};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use probes::tap;
use redbpf::load::Loader;



mod utils;


/// Get the eBPF program to inject
fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/tap/tap.elf",
    ))
}

fn fdpid_to_path(st: tap::FdPid) -> Result<String, Box<dyn Error>> {
    let path = format!("/proc/{}/fd/{}", st.pid, st.fd);
    let path = std::path::Path::new(&path);
    let path = path.read_link()?;
    let path = path.to_str().unwrap();
    Ok(path.to_string())
}





#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let mut loaded = Loader::load(probe_code()).expect("error in Loader::load");

    let probe = loaded
        .kprobe_mut("chdir_entry")
        .expect("error on Loaded::kprobe_mut [chdir_entry]");

    probe
        .attach_kprobe("__x64_sys_chdir", 0)
        .expect("error on KProbe::attach_kprobe [__x64_sys_chdir]");

    probe
        .attach_kprobe("__ia32_sys_chdir", 0)
        .expect("error on KProbe::attach_kprobe [__ia32_sys_chdir]");

    let fprobe = loaded
        .kprobe_mut("fchdir_entry")
        .expect("error on Loaded::kprobe_mut [fchdir_entry]");

    fprobe
        .attach_kprobe("__x64_sys_fchdir", 0)
        .expect("error on KProbe::attach_kprobe [__x64_sys_fchdir]");

    fprobe
        .attach_kprobe("__ia32_sys_fchdir", 0)
        .expect("error on KProbe::attach_kprobe [__ia32_sys_fchdir]");

    // Event Loop
    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "CHDIR_MAP" {
            std::thread::spawn(move || {
                let paths: Vec<String> = events
                    .iter()
                    .map(|event| {
                        let path = unsafe { ptr::read(event.as_ptr() as *const tap::Path) };

                        let path = unsafe {
                            let cfn = CStr::from_ptr(path.path.as_ptr() as *const _);
                            cfn.to_str().unwrap()
                        }
                        .to_string();
                        path
                    })
                    .collect();

                // Task to perform from current batch of events
                for path in paths {
                    println!("{}", path);
                }
            });
        } else if map_name == "FCHDIR_MAP" {
            std::thread::spawn(move || {
                let paths: Vec<String> = events
                    .iter()
                    .map(|event| {
                        let fdpid = unsafe { ptr::read(event.as_ptr() as *const tap::FdPid) };

                        let path = fdpid_to_path(fdpid).unwrap();

                        path
                    })
                    .collect();

                // Task to perform from current batch of events
                for path in paths {
                    println!("{}", path);
                }
            });
        }
    }

    Ok(())
}
