use futures::StreamExt;
use std::{
    collections::HashMap,
    error::Error,
    ffi::CStr,
    ptr,
    time::{Duration, Instant},
};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use probes::tap;
use redbpf::load::Loader;

use std::sync::mpsc::channel;

mod utils;

use utils::ops::filter;

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

const COOLDOWN_TIME: Duration = Duration::new(5, 0);

#[tokio::main]
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

    let (tx, rx) = channel::<Vec<String>>();

    let stash: HashMap<String, Instant> = HashMap::new();
    // Make stash multithreading safe
    let stash = std::sync::Arc::new(std::sync::Mutex::new(stash));

    std::thread::spawn(move || {
        while let Ok(paths) = rx.recv() {
            let mut stash = stash.lock().unwrap();
            for path in paths {
                if stash.contains_key(&path) {
                    if stash[&path].elapsed() < COOLDOWN_TIME {
                        continue;
                    } else {
                        stash.remove(&path);
                    }
                }
                if !filter(&path) {
                    continue;
                }


                // Operation to be performed for path that are newly added
                println!("{}", path);

                stash.insert(path, Instant::now());
            }
        }
    });

    // Event Loop
    while let Some((map_name, events)) = loaded.events.next().await {
        let tx = tx.clone();
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

                tx.send(paths).unwrap();
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
                tx.send(paths).unwrap();
            });
        }
    }
    Ok(())
}
