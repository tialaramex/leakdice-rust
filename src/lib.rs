#![warn(rust_2018_idioms)]

//! leakdice is useful when for some reason a methodical approach to identifying memory leaks isn't available
//! e.g. because the process is already running and it's too late to instrument it.
//! leakdice was inspired in part by Raymond Chen's blog article "The poor man's way of identifying memory leaks"

use std::env;
use std::ffi::OsString;
use std::num::NonZeroU32;
use std::num::NonZeroUsize;

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

const PAGE_SIZE: usize = 4096;

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

    use std::io;
    ascii_hex(io::stdout(), addr, &buffer)
}

const ADDR_BYTES: usize = std::mem::size_of::<usize>();
const LINE_SIZE: usize = 16;

fn ascii_hex<W>(mut out: W, addr: usize, buffer: &[u8; PAGE_SIZE]) -> Result<()>
where
    W: std::io::Write,
{
    use std::borrow::BorrowMut;

    let mut old_slice = &buffer[..0];
    let mut repeat = false;
    for line in 0..(PAGE_SIZE / LINE_SIZE) {
        let offset = line * LINE_SIZE;
        let slice = &buffer[offset..(offset + LINE_SIZE)];
        if slice != old_slice {
            ascii_row(out.borrow_mut(), addr + offset, slice)?;
            repeat = false;
        } else if !repeat {
            write!(out, " ...\n")?;
            repeat = true;
        }
        old_slice = slice;
    }
    Ok(())
}

fn ascii_row<W>(mut out: W, addr: usize, buffer: &[u8]) -> Result<()>
where
    W: std::io::Write,
{
    write!(out, "{addr:0size$x} ", size = ADDR_BYTES * 2, addr = addr)?;
    for byte in buffer {
        if *byte > 31 && *byte < 127 {
            write!(out, "{}", (*byte as char))?;
        } else {
            write!(out, ".")?;
        }
    }
    for byte in buffer {
        write!(out, " {:02x}", byte)?;
    }
    write!(out, "\n")?;

    Ok(())
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
    let mut page: usize = rng.gen_range(0..=pages) - 1;

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

#[derive(Debug, PartialEq, Eq)]
struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Memory {
    pub start: usize,
    pub pages: usize,
    pub perms: MemoryPermissions,
    pub offset: usize,
}

impl Memory {
    fn new(start: usize, end: usize, r: char, w: char, x: char, p: char, offset: usize) -> Memory {
        let read = match r {
            'r' => true,
            _ => false,
        };
        let write = match w {
            'w' => true,
            _ => false,
        };
        let execute = match x {
            'x' => true,
            _ => false,
        };
        let shared = match p {
            's' => true,
            _ => false,
        };

        let perms = MemoryPermissions {
            read,
            write,
            execute,
            shared,
        };
        let pages = (end - start) / PAGE_SIZE;

        Memory {
            start,
            pages,
            perms,
            offset,
        }
    }
}

fn match_to_one_char(m: regex::Match<'_>) -> char {
    m.as_str()
        .chars()
        .next()
        .expect("Match was unexpectedly empty")
}

fn memory_map<L>(lines: L) -> Result<Vec<Memory>>
where
    L: Iterator<Item = std::io::Result<String>>,
{
    use regex::Regex;
    let re = Regex::new("^([[:xdigit:]]+)-([[:xdigit:]]+) (.)(.)(.)(.) ([[:xdigit:]]+)")
        .expect("Memory-map matching regular expression should compile");

    let mut vec = Vec::new();

    for line in lines {
        if let Ok(line) = line {
            let cap = re
                .captures(&line)
                .expect("Incompatible layout of /proc/pid/maps");
            if let Some(offset) = cap.get(7) {
                let start = cap.get(1).unwrap();
                let end = cap.get(2).unwrap();
                let r = match_to_one_char(cap.get(3).unwrap());
                let w = match_to_one_char(cap.get(4).unwrap());
                let x = match_to_one_char(cap.get(5).unwrap());
                let p = match_to_one_char(cap.get(6).unwrap());

                let start = usize::from_str_radix(start.as_str(), 16)?;
                let end = usize::from_str_radix(end.as_str(), 16)?;
                let offset = usize::from_str_radix(offset.as_str(), 16)?;
                vec.push(Memory::new(start, end, r, w, x, p, offset));
            }
        } else {
            return Err(anyhow!("Trouble reading /proc/pid/maps"));
        }
    }

    Ok(vec)
}

#[cfg(test)]
#[test]
fn ar_zero() {
    let row: [u8; LINE_SIZE] = [0; LINE_SIZE];

    use std::io;
    let result = ascii_row(io::sink(), 0x12345678, &row);

    assert!(result.is_ok());
}

#[test]
fn ar_easy() {
    let row: [u8; LINE_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    use std::io;
    let result = ascii_row(io::sink(), 0x12345678, &row);

    assert!(result.is_ok());
}

#[test]
fn ar_letters() {
    let row: [u8; LINE_SIZE] = [
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    ];

    use std::io;
    let result = ascii_row(io::sink(), 0x12345678, &row);

    assert!(result.is_ok());
}

#[test]
fn ah_zero() {
    let page: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    use std::io;
    let result = ascii_hex(io::sink(), 0x12345678, &page);

    assert!(result.is_ok());
}

#[test]
fn ah_ascending() {
    let mut page: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    for n in 0..PAGE_SIZE {
        page[n] = n as u8;
    }

    use std::io;
    let result = ascii_hex(io::sink(), 0x12345678, &page);

    assert!(result.is_ok());
}

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
