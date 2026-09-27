//! Managed-console preparation; authentication remains entirely PGSS Logon.
use peios::registry::{Key, KeyAccess, OpenFlags};

pub(super) fn prepare() -> Result<(), String> {
    reset_terminal()?;
    let mut announced = false;
    loop {
        let pending = setup_pending(|path| {
            match Key::open(None, path, KeyAccess::QUERY_VALUE, OpenFlags::default()) {
                Ok(_) => Ok(true),
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(false),
                Err(e) => Err(format!("cannot check first-boot setup: {e}")),
            }
        })?;
        if !pending {
            break;
        }
        if !announced {
            println!("First-boot setup is in progress on the system console.");
            announced = true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    // Discard input typed while setup was still running.
    reset_terminal()
}

fn setup_pending(mut exists: impl FnMut(&str) -> Result<bool, String>) -> Result<bool, String> {
    for service in ["oobed", "oobe-tui"] {
        if exists(&format!("Machine\\System\\Services\\{service}"))? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn reset_terminal() -> Result<(), String> {
    let mut settings: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut settings) } != 0 {
        return Err(format!(
            "read console settings: {}",
            std::io::Error::last_os_error()
        ));
    }
    sane(&mut settings);
    if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &settings) } != 0 {
        return Err(format!(
            "reset console settings: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn sane(t: &mut libc::termios) {
    // Preserve baud rate and framing: this can also be a serial console.
    t.c_iflag &= !(libc::IGNBRK | libc::INLCR | libc::IGNCR | libc::ISTRIP | libc::IXOFF);
    t.c_iflag |= libc::BRKINT | libc::ICRNL | libc::IXON;
    t.c_oflag |= libc::OPOST | libc::ONLCR;
    t.c_lflag |= libc::ISIG | libc::ICANON | libc::IEXTEN | libc::ECHO | libc::ECHOE | libc::ECHOK;
    t.c_lflag &= !(libc::ECHONL | libc::NOFLSH | libc::TOSTOP | libc::EXTPROC);
    for (index, value) in [
        (libc::VINTR, 3),
        (libc::VQUIT, 28),
        (libc::VERASE, 127),
        (libc::VKILL, 21),
        (libc::VEOF, 4),
        (libc::VSTART, 17),
        (libc::VSTOP, 19),
        (libc::VSUSP, 26),
        (libc::VLNEXT, 22),
        (libc::VWERASE, 23),
        (libc::VREPRINT, 18),
        (libc::VMIN, 1),
        (libc::VTIME, 0),
    ] {
        t.c_cc[index] = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_gate_fails_closed_and_waits_for_both_retirements() {
        assert!(setup_pending(|_| Err("registry unavailable".into())).is_err());
        assert!(setup_pending(|p| Ok(p.ends_with("oobed"))).unwrap());
        assert!(setup_pending(|p| Ok(p.ends_with("oobe-tui"))).unwrap());
        assert!(!setup_pending(|_| Ok(false)).unwrap());
    }
    #[test]
    fn raw_noecho_terminal_returns_to_login_mode_without_changing_serial_speed() {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        t.c_cflag = libc::B115200 | libc::CS8 | libc::CREAD;
        let framing = t.c_cflag;
        sane(&mut t);
        assert_eq!(t.c_cflag, framing);
        assert_ne!(t.c_lflag & libc::ICANON, 0);
        assert_ne!(t.c_lflag & libc::ECHO, 0);
        assert_ne!(t.c_lflag & libc::ISIG, 0);
        assert_eq!(t.c_cc[libc::VINTR], 3);
        assert_eq!(t.c_cc[libc::VEOF], 4);
    }
}
