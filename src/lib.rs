#![warn(rust_2018_idioms)]

//! leakdice is useful when for some reason a methodical approach to identifying memory leaks isn't available
//! e.g. because the process is already running and it's too late to instrument it.
//! leakdice was inspired in part by Raymond Chen's blog article "The poor man's way of identifying memory leaks"

use std::env;
use std::ffi::OsString;
use std::num::{NonZeroU32, NonZeroUsize};

use anyhow::anyhow;
use anyhow::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct Settings {
    pub name: String,
    pub pid: Option<NonZeroU32>,
    pub addr: Option<NonZeroUsize>,
}

pub fn read_args() -> Result<Settings> {
    read_args_internal(env::args_os())
}

pub fn execute(settings: Settings) -> Result<()> {
    let pid = settings
        .pid
        .expect("Shouldn't call this without setting pid");

    let addr = match settings.addr {
        Some(addr) => addr.get(),
        None => pick_offset(settings)?,
    };

    /* Fix up addr to align one page */
    let addr = addr & (usize::MAX - (PAGE_SIZE - 1));

    let procfile = format!("/proc/{}/mem", pid);

    let mut fd: std::fs::File = match OpenOptions::new().read(true).open(&procfile) {
        Ok(fd) => fd,
        Err(x) => {
            return match x.kind() {
                ErrorKind::NotFound => Err(anyhow!(
                    "Non-existent process, pick a process which actually exists"
                )),
                ErrorKind::PermissionDenied => Err(anyhow!(
                    "Permission denied, pick a process owned by this user"
                )),
                _ => Err(anyhow!(x)),
            }
        }
    };

    use std::convert::TryInto;
    let offset: u64 = addr.try_into().unwrap();
    use std::io::Seek;
    let pos = fd.seek(std::io::SeekFrom::Start(offset))?;
    if pos != offset {
        return Err(anyhow!(
            "Somehow unable to seek to {:08x} in {}",
            offset,
            procfile
        ));
    }

    let mut buffer = [0; PAGE_SIZE];
    use std::io::Read;
    let read = fd.read(&mut buffer[..])?;
    if read != PAGE_SIZE {
        return Err(anyhow!(
            "Somehow only able to read {} bytes from {}",
            read,
            procfile
        ));
    }

    let mut stdout = std::io::stdout();
    let (addr_width, spaces) = row_diet(addr);
    let output = Output::new(&mut stdout, addr_width, spaces);
    ascii_page(output, addr, &buffer)
}

fn read_args_internal<A>(mut args: A) -> Result<Settings>
where
    A: Iterator<Item = OsString>,
{
    let name = match args.next() {
        Some(name) => name.into_string().unwrap(),
        None => "Unknown".to_string(),
    };

    let pid = pid_from_dec(args.next())?;

    let addr = addr_from_hex(args.next())?;

    Ok(Settings { name, pid, addr })
}

fn pid_from_dec(s: Option<OsString>) -> Result<Option<NonZeroU32>> {
    let arg = match s {
        Some(s) => s,
        None => return Ok(None),
    };

    let z = arg.into_string();

    let arg = match z {
        Ok(s) => s,
        Err(_) => return Err(anyhow!("Ugh")),
    };

    match arg.parse::<u32>() {
        Ok(0) => Err(anyhow!("Blergh")),
        Ok(num) => Ok(NonZeroU32::new(num)),
        Err(_) => Err(anyhow!("Ppfffffft")),
    }
}

fn addr_from_hex(s: Option<OsString>) -> Result<Option<NonZeroUsize>> {
    let arg = match s {
        None => return Ok(None),
        Some(s) => s,
    };

    let z = arg.into_string();

    let arg = match z {
        Ok(s) => s,
        Err(_) => return Err(anyhow!("Ugh")),
    };

    match usize::from_str_radix(&arg, 16) {
        Ok(0) => Err(anyhow!("Blergh")),
        Ok(num) => Ok(NonZeroUsize::new(num)),
        Err(_) => Err(anyhow!("Fffft")),
    }
}

use std::fs::OpenOptions;
use std::io::ErrorKind;

mod hexdump;
use hexdump::ascii_page;
use hexdump::Output;
use hexdump::LINE_SIZE;
use hexdump::PAGE_SIZE;

const ADDR_BYTES: usize = std::mem::size_of::<usize>();

fn row_diet(addr: usize) -> (usize, bool) {
    use terminal_size::{terminal_size, Width};
    let size = terminal_size();
    let zeros = (ADDR_BYTES * 2) - (addr.leading_zeros() as usize / 4);

    if let Some((Width(w), _)) = size {
        if w as usize >= (ADDR_BYTES * 2) + (LINE_SIZE * 4) + 2 {
            return (ADDR_BYTES * 2, true);
        } else if w as usize >= zeros + (LINE_SIZE * 4) + 2 {
            return (zeros, true);
        } else if w as usize >= (ADDR_BYTES * 2) + (LINE_SIZE * 3) + 2 {
            return (ADDR_BYTES * 2, false);
        } else {
            return (zeros, false);
        }
    }
    (ADDR_BYTES * 2, true)
}

fn pick_offset(settings: Settings) -> Result<usize> {
    let pid = settings
        .pid
        .expect("Shouldn't call this without setting pid");

    let procfile = format!("/proc/{}/maps", pid);

    let fd: std::fs::File = match OpenOptions::new().read(true).open(&procfile) {
        Ok(fd) => fd,
        Err(x) => {
            return match x.kind() {
                ErrorKind::NotFound => Err(anyhow!(
                    "Non-existent process, pick a process which actually exists"
                )),
                ErrorKind::PermissionDenied => Err(anyhow!(
                    "Permission denied, pick a process owned by this user"
                )),
                _ => Err(anyhow!(x)),
            }
        }
    };

    use std::io::{self, BufRead};
    pick_offset_from_map(io::BufReader::new(fd).lines())
}

mod memory;
use memory::memory_map;
use memory::MemoryPermissions;

fn pick_offset_from_map<L>(lines: L) -> Result<usize>
where
    L: Iterator<Item = std::io::Result<String>>,
{
    let perms = MemoryPermissions {
        read: true,
        write: true,
        execute: false,
        shared: false,
    };

    let mem = memory_map(lines)?;
    let pages: usize = mem
        .iter()
        .filter(|m| m.perms == perms)
        .map(|m| m.pages)
        .sum();
    if pages == 0 {
        return Err(anyhow!("Process appears to have no heap"));
    }

    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let mut page: usize = rng.gen_range(0..pages);

    let heap = mem.iter().filter(|m| m.perms == perms);

    for range in heap {
        if range.pages <= page {
            page -= range.pages;
        } else {
            return Ok(range.start + (PAGE_SIZE * page));
        }
    }

    panic!("Somehow there were fewer pages than we earlier calculated!");
}

#[cfg(test)]
#[test]
fn pfd_none() {
    let result = pid_from_dec(None);
    let inner = result.expect("tried to parse empty argument");

    assert_eq!(inner, None);
}

#[test]
#[should_panic(expected = "Not a number")]
fn pfd_space() {
    let space = Some(OsString::from(" "));

    let result = pid_from_dec(space);
    let _ = result.expect("Not a number");
}

#[test]
fn pfd_five() {
    let five = Some(OsString::from("5"));

    let result = pid_from_dec(five);
    let inner = result.expect("unable to parse five");

    assert_eq!(inner, NonZeroU32::new(5));
}

#[test]
fn afh_none() {
    let result = addr_from_hex(None);
    let inner = result.expect("tried to parse empty argument");

    assert_eq!(inner, None);
}

#[test]
#[should_panic(expected = "Not a number")]
fn afh_space() {
    let space = Some(OsString::from(" "));

    let result = addr_from_hex(space);
    let _ = result.expect("Not a number");
}

#[test]
fn afh_fives() {
    let fives = Some(OsString::from("55555555"));

    let result = addr_from_hex(fives);
    let inner = result.expect("unable to parse fives");

    assert_eq!(inner, NonZeroUsize::new(0x55555555));
}

#[test]
fn rai_empty() {
    let name = "Unknown".to_string();
    let empty = Settings {
        name,
        pid: None,
        addr: None,
    };
    let nothing: Vec<OsString> = Vec::new();

    let result = read_args_internal(nothing.iter().cloned()).unwrap();

    assert_eq!(result, empty);
}

#[test]
fn rai_example1() {
    let name = "program_name".to_string();
    let expected = Settings {
        name,
        pid: NonZeroU32::new(1234),
        addr: None,
    };
    let mut example: Vec<OsString> = Vec::new();

    example.push(OsString::from("program_name"));
    example.push(OsString::from("1234"));

    let result = read_args_internal(example.iter().cloned()).unwrap();

    assert_eq!(result, expected);
}

#[test]
fn rai_example2() {
    let name = "program_name".to_string();
    let expected = Settings {
        name,
        pid: NonZeroU32::new(5678),
        addr: NonZeroUsize::new(0xdeadbeef),
    };
    let mut example: Vec<OsString> = Vec::new();

    example.push(OsString::from("program_name"));
    example.push(OsString::from("5678"));
    example.push(OsString::from("DEADBEEF"));

    let result = read_args_internal(example.iter().cloned()).unwrap();

    assert_eq!(result, expected);
}
