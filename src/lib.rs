#[macro_use]
extern crate lazy_static;

use auxtools::raw_types::funcs::CURRENT_EXECUTION_CONTEXT;
use auxtools::raw_types::procs::ProcId;
use auxtools::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::processthreadsapi::{GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread};
use winapi::um::winnt::{HANDLE, THREAD_SUSPEND_RESUME};

static STOP_SAMPLING: AtomicBool = AtomicBool::new(false);

/// Miliseconds to sleep between each sample,
/// by default 2 milis for 500 samples per second
static SAMPLE_SLEEP_TIME: AtomicU64 = AtomicU64::new(2);

/// The BYOND thread which runs game code and other internal stuff
/// Not protected with any synchronization because, come on, it's
/// written to once at the start then only read
static mut BYOND_MAIN_THREAD: HANDLE = std::ptr::null_mut();

lazy_static! {
    static ref SAMPLES: Mutex<HashMap<ProcId, usize>> = Mutex::new(HashMap::new());
}

fn sampling_loop() {
    loop {
        unsafe {
            SuspendThread(BYOND_MAIN_THREAD);

            let ctx_ptr = *CURRENT_EXECUTION_CONTEXT;
            let proc_id;

            if ctx_ptr.is_null() {
                // If there's no execution context, we're inside byond internals
                // using u32 max value as flag
                proc_id = ProcId(u32::max_value());
            } else {
                let ctx = &*ctx_ptr;
                proc_id = (*ctx.proc_instance).proc;
            }

            SAMPLES
                .lock()
                .unwrap()
                .entry(proc_id)
                .and_modify(|e| *e += 1)
                .or_insert(1);

            ResumeThread(BYOND_MAIN_THREAD);
        }
        thread::sleep(Duration::from_millis(
            SAMPLE_SLEEP_TIME.load(Ordering::Relaxed),
        ));
        if STOP_SAMPLING.load(Ordering::Relaxed) {
            break;
        }
    }
}

#[init(full)]
fn init_sampling() -> Result<(), String> {
    // This is running in the main BYOND thread, so we can easily get the handle to it
    unsafe {
        BYOND_MAIN_THREAD = OpenThread(THREAD_SUSPEND_RESUME, 0, GetCurrentThreadId());
        if BYOND_MAIN_THREAD == INVALID_HANDLE_VALUE {
            return Err(String::from("Failed to open main thread"));
        }
    }
    Ok(())
}

#[hook("/proc/enable_sampling")]
fn enable_sampling() {
    STOP_SAMPLING.store(false, Ordering::Relaxed);
    thread::spawn(|| sampling_loop());
    Ok(Value::from(true))
}

fn disable_sampling() {
    STOP_SAMPLING.store(true, Ordering::Relaxed);
}

#[hook("/proc/disable_sampling")]
fn disable_sampling_proxy() {
    disable_sampling();
    Ok(Value::from(true))
}

#[hook("/proc/set_sample_rate")]
fn set_sample_rate(rate: Value) {
    let rate = rate
        .as_number()
        .map_err(|_| runtime!("Non-numeric value passed to set_sample_rate"))?;

    if rate <= 0.0 {
        return Err(runtime!("Sample rate must be greater than zero"));
    }

    SAMPLE_SLEEP_TIME.store((1000.0 / rate) as u64, Ordering::Relaxed);
    Ok(Value::from(true))
}

#[hook("/proc/dump_samples")]
fn dump_samples() {
    let path = Path::new("samples.txt");
    let mut outfile = match File::create(path) {
        Err(why) => return Err(runtime!("couldn't create {}: {}", path.display(), why)),
        Ok(file) => file,
    };

    for (proc_id, calls) in SAMPLES.lock().unwrap().iter() {
        let proc_path;
        if (*proc_id).0 == u32::max_value() {
            proc_path = String::from("(byond internals)");
        } else if let Some(proc) = Proc::from_id(*proc_id) {
            proc_path = proc.path;
        } else {
            proc_path = String::from("(unknown proc)");
        }

        match write!(outfile, "{}: {}\n", proc_path, calls) {
            Ok(_) => (),
            Err(e) => return Err(runtime!("failed to write to {}: {}", path.display(), e)),
        }
    }
    Ok(Value::from(true))
}

#[shutdown]
fn shut_down_sampling() {
    disable_sampling();
}
