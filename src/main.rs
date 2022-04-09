extern crate battery;
extern crate env_logger;
extern crate futures;
extern crate libc;
extern crate log;
extern crate regex;
extern crate tokio;

use std::env;
use std::error::Error;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::result::Result;
use std::str;
use std::task::Context;
use std::task::Poll;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::signal::unix::{signal, SignalKind};

use futures::ready;

use battery::units::ratio::percent;
use battery::units::thermodynamic_temperature::degree_celsius;

use regex::Regex;

use env_logger::Env;

use log::debug;

struct NotifyFd {
    fd: RawFd,
    pub token: c_int,
}

impl NotifyFd {
    fn new(key: &str) -> Result<Self, Box<dyn Error>> {
        let mut token = MaybeUninit::<c_int>::uninit();
        let mut nfd = MaybeUninit::<RawFd>::uninit();
        unsafe {
            let key = CString::new(key).unwrap();
            let r = notify_register_file_descriptor(
                key.as_ptr(),
                nfd.as_mut_ptr(),
                0,
                token.as_mut_ptr(),
            );
            if r != 0 {
                return Err("notify_register_file_descriptor failed".into());
            }
        }
        let token = unsafe { token.assume_init() };
        let nfd = unsafe { nfd.assume_init() };

        Ok(NotifyFd { fd: nfd, token })
    }
}

impl Read for NotifyFd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let r = libc::read(self.fd, buf.as_mut_ptr() as *mut c_void, buf.len());
            if r == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(r as usize)
            }
        }
    }
}

impl Drop for NotifyFd {
    fn drop(&mut self) {
        unsafe {
            let r = notify_cancel(self.token);
            if r != 0 {
                panic!("notify_cancel failed");
            }
        }
    }
}

// Needed for integration with Tokio
impl AsRawFd for NotifyFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

struct AsyncNotifyFd {
    inner: AsyncFd<NotifyFd>,
    pub token: c_int,
}

impl AsyncNotifyFd {
    fn new(key: &str) -> Result<Self, Box<dyn Error>> {
        let mut nfd = NotifyFd::new(key)?;

        // Suspend the events while we adjust the fd
        unsafe {
            let r = notify_suspend(nfd.token);
            if r != 0 {
                return Err("notify_suspend failed".into());
            }
        }

        // Set the file descriptor in non blocking mode
        unsafe {
            let flags = libc::fcntl(nfd.fd, libc::F_GETFL);
            let r = libc::fcntl(nfd.fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            if r != 0 {
                return Err("fcntl failed".into());
            }
        }

        // Drain the file descriptor of all data before registering with Tokio
        loop {
            let mut buf = [0; 4];
            match nfd.read_exact(&mut buf) {
                Ok(_) => {
                    continue;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break;
                    } else {
                        return Err(format!("unexpected read io error {}", e).into());
                    }
                }
            }
        }

        let t = nfd.token;

        // Register the file descriptor with tokio
        let afd = AsyncFd::with_interest(nfd, Interest::READABLE)?;

        // Resume events
        unsafe {
            let r = notify_resume(t);
            if r != 0 {
                return Err("notify_resume failed".into());
            }
        }

        Ok(Self {
            inner: afd,
            token: t,
        })
    }
}

impl AsyncRead for AsyncNotifyFd {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready_mut(cx))?;
            let r = guard.try_io(|x| x.get_mut().read(buf.initialize_unfilled()));
            if r.is_ok() {
                return Poll::Ready(r.unwrap().map(|r| buf.advance(r)));
            }
        }
    }
}

fn get_is_temperature_safe_for_charge(
    battery: &battery::Battery,
    temperature_high_limit: f32,
) -> bool {
    battery
        .temperature()
        .ok_or(0)
        .unwrap()
        .get::<degree_celsius>()
        < temperature_high_limit
}

fn get_is_charging_enabled(smc_path: &Path) -> bool {
    let key_read_output = Command::new(&smc_path)
        .args(["-k", "CH0B", "-r"])
        .output()
        .expect("failed to execute process");
    let key_bytes_re = Regex::new(r"bytes (?P<bytes>\d{2})").unwrap();

    match &key_bytes_re.captures(&String::from_utf8(key_read_output.stdout).unwrap()) {
        None => true,
        Some(val) => (&val["bytes"] == "00"),
    }
}

fn enable_charging(smc_path: &Path, should_enable: bool) -> bool {
    debug!("enable_charging: {}", should_enable);

    let keys = vec!["CH0B", "CH0C"];
    let bytes = if should_enable { "00" } else { "02" };
    for key in keys.into_iter() {
        Command::new("sudo")
            .arg(&smc_path)
            .args(["-k", key, "-w", bytes])
            .output()
            .expect("failed to execute process");
    }

    should_enable
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let env = Env::default().filter_or("LOG_LEVEL", "off");
    env_logger::init_from_env(env);

    let smc_path = match env::var("SMC_PATH") {
        Ok(val) => PathBuf::from(val),
        Err(_e) => {
            let sibling_path = env::current_exe().unwrap().parent().unwrap().join("smc");
            match fs::metadata(&sibling_path).is_ok() {
                true => sibling_path,
                false => PathBuf::from(
                    option_env!("SMC_PATH").expect("set SMC_PATH environment variable"),
                ),
            }
        }
    };
    let manager = battery::Manager::new()?;
    let mut battery = manager.batteries()?.next().ok_or("no battery found")??;

    let stage_of_charge_low_limit: f32 = 48.0;
    let stage_of_charge_high_limit: f32 = 52.0;
    let temperature_high_limit: f32 = 32.0;

    let mut is_charging_enabled: bool = get_is_charging_enabled(&smc_path);
    debug!("is_charging_enabled: {:?}", is_charging_enabled);

    if std::env::args().nth(1).unwrap_or_default() == "--read" {
        println!(
            "is_charging_enabled: {:?}; is_temperature_safe_for_charge: {:?}",
            is_charging_enabled,
            get_is_temperature_safe_for_charge(&battery, temperature_high_limit)
        );
        return Ok(());
    }

    let mut was_charging_enabled_at_sleep: bool = false;

    let mut power_nfd = AsyncNotifyFd::new("com.apple.system.powersources.timeremaining")?;
    let mut power_buf = [0; 4];
    let mut sleep_nfd = AsyncNotifyFd::new("com.apple.powermanagement.systempowerstate")?;
    let mut sleep_buf = [0; 4];
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                enable_charging(&smc_path, true);
                break;
            },
            _ = sigterm.recv() => {
                enable_charging(&smc_path, true);
                break;
            },
            _ = sleep_nfd.read_exact(&mut sleep_buf) => {
                if is_charging_enabled {
                    is_charging_enabled = enable_charging(&smc_path, false);
                    was_charging_enabled_at_sleep = true;
                }
            },
            _ = power_nfd.read_exact(&mut power_buf) => {
                let is_temperature_safe_for_charge = get_is_temperature_safe_for_charge(
                    &battery,
                    temperature_high_limit
                );

                if was_charging_enabled_at_sleep {
                    if is_temperature_safe_for_charge
                        && battery.state_of_charge().get::<percent>() < stage_of_charge_high_limit {
                        is_charging_enabled = enable_charging(&smc_path, true);
                        debug!("continue charging, interrupted at sleep");
                    }
                    was_charging_enabled_at_sleep = false;
                } else if !is_charging_enabled
                    && is_temperature_safe_for_charge
                    && battery.state_of_charge().get::<percent>() <= stage_of_charge_low_limit
                {
                    is_charging_enabled = enable_charging(&smc_path, true)
                } else if is_charging_enabled
                    && battery.state_of_charge().get::<percent>() >= stage_of_charge_high_limit
                {
                    is_charging_enabled = enable_charging(&smc_path, false)
                } else if !is_temperature_safe_for_charge {
                    is_charging_enabled = enable_charging(&smc_path, is_temperature_safe_for_charge);
                }

                debug!(
                    "state_of_charge: {:?}; is_temperature_safe_for_charge: {:?}; is_charging_enabled: {:?}",
                    battery.state_of_charge(),
                    is_temperature_safe_for_charge,
                    is_charging_enabled,
                );

                let v = c_int::from_be_bytes(power_buf);
                if v == power_nfd.token {
                    manager.refresh(&mut battery)?;
                } else {
                    return Err("unknown token in file descriptor!".into());
                }
            }
        }
    }
    Ok(())
}

extern "C" {
    pub fn notify_register_file_descriptor(
        name: *const c_char,
        notify_fd: *mut c_int,
        flags: c_int,
        out_token: *mut c_int,
    ) -> u32;

    pub fn notify_cancel(token: c_int) -> u32;

    // Added to allow safely setting the fd to non blocking mode
    pub fn notify_suspend(token: ::std::os::raw::c_int) -> u32;
    pub fn notify_resume(token: ::std::os::raw::c_int) -> u32;
}
