use std::env;
use std::ffi::OsString;

use anyhow::anyhow;
use anyhow::Result;

#[derive(Debug,PartialEq,Eq)]
pub struct Settings {
    pub name: String,
    pub pid: Option<i32>,
    pub addr: Option<usize>,
}

pub fn read_args() -> Result<Settings> {
    read_args_internal(env::args_os())
}

fn read_args_internal<A>(mut args: A) -> Result<Settings> where
    A: Iterator<Item = OsString> {
    let name = match args.next() {
        Some(name) => name.into_string().unwrap(),
        None => "Unknown".to_string(),
    };

    let pid = pid_from_dec(args.next())?;

    let addr = addr_from_hex(args.next())?;
    /* Fix up to align one page */

    Ok(Settings { name, pid, addr })
}

fn pid_from_dec(s: Option<OsString>) -> Result<Option<i32>> {
    let arg = match s {
        None => return Ok(None),
        Some(s) => s,
    };

    let z = arg.into_string();

    let arg = match z {
        Ok(s) => s,
        Err(_) => return Err(anyhow!("Ugh")),
    };

    match arg.parse::<i32>() {
        Ok(num) => Ok(Some(num)),
        Err(_) => Err(anyhow!("Ppfffffft")),
    }
}

fn addr_from_hex(s: Option<OsString>) -> Result<Option<usize>> {

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
        Ok(num) => Ok(Some(num)),
        Err(_) => Err(anyhow!("Fffft")),
    }
}

use std::fs::OpenOptions;
use std::io::ErrorKind;

const PAGE_SIZE: usize = 4096;

pub fn doit(settings: Settings) -> Result<()> {
    let pid = settings.pid.expect("Shouldn't call this without setting pid");

    let addr = match settings.addr {
        Some(addr) => addr,
        None => pick_offset(settings)?,
    };

    let procfile = format!("/proc/{}/mem", pid);

    let mut fd: std::fs::File = match OpenOptions::new().read(true).open(&procfile) {
        Ok(fd) => fd,
        Err(x) => return match x.kind() {
            ErrorKind::NotFound => Err(anyhow!("Non-existent process, pick a process which actually exists")),
            ErrorKind::PermissionDenied => Err(anyhow!("Permission denied, pick a process owned by this user")),
            _ => Err(anyhow!(x)),
        }
    };

    use std::convert::TryInto;
    let offset: u64 = addr.try_into().unwrap();
    use std::io::Seek;
    let pos = fd.seek(std::io::SeekFrom::Start(offset))?;
    if pos != offset {
        return Err(anyhow!("Somehow unable to seek to {:08x} in {}", offset, procfile));
    }

    let mut buffer = [0; PAGE_SIZE];
    use std::io::Read;
    let read = fd.read(&mut buffer[..])?;
    if read != PAGE_SIZE {
        return Err(anyhow!("Somehow only able to read {} bytes from {}", read, procfile));
    }

    use std::io;
    ascii_hex(io::stdout(), addr, &buffer)
}

const ADDR_BYTES: usize = std::mem::size_of::<usize>();
const LINE_SIZE: usize = 16;

fn ascii_hex<W>(mut out: W, addr: usize, buffer: &[u8; PAGE_SIZE]) -> Result<()> where
    W: std::io::Write {

    use std::borrow::BorrowMut;

    let mut old_slice = &buffer[..0];
    let mut repeat = false;
    for line in 0..(PAGE_SIZE/LINE_SIZE) {
        let offset = line * LINE_SIZE;
        let slice = &buffer[offset..(offset+LINE_SIZE)];
        if slice != old_slice {
            ascii_row(out.borrow_mut(), addr+offset, slice)?;
            repeat = false;
        } else if !repeat {
            write!(out, " ...\n")?;
            repeat = true;
        }
        old_slice = slice;
    }
    Ok(())
}

fn ascii_row<W>(mut out: W, addr: usize, buffer: &[u8]) -> Result<()> where
    W: std::io::Write {

    write!(out, "{addr:0size$x} ", size= ADDR_BYTES, addr= addr)?;
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
    /* Read maps etc. */
    todo!();
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
    let row: [u8; LINE_SIZE] = [64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79];

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

    assert_eq!(inner, Some(5));
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

    assert_eq!(inner, Some(0x55555555));
}


#[test]
fn rai_empty() {
    let name = "Unknown".to_string();
    let empty = Settings { name, pid: None, addr: None };
    let nothing: Vec<OsString> = Vec::new();

    let result = read_args_internal(nothing.iter().cloned()).unwrap();

    assert_eq!(result, empty);
}

#[test]
fn rai_example1() {
    let name = "program_name".to_string();
    let expected = Settings { name, pid: Some(1234), addr: None };
    let mut example: Vec<OsString> = Vec::new();

    example.push(OsString::from("program_name"));
    example.push(OsString::from("1234"));

    let result = read_args_internal(example.iter().cloned()).unwrap();

    assert_eq!(result, expected);
}

#[test]
fn rai_example2() {
    let name = "program_name".to_string();
    let expected = Settings { name, pid: Some(5678), addr: Some(0xdeadbeef) };
    let mut example: Vec<OsString> = Vec::new();

    example.push(OsString::from("program_name"));
    example.push(OsString::from("5678"));
    example.push(OsString::from("DEADBEEF"));

    let result = read_args_internal(example.iter().cloned()).unwrap();

    assert_eq!(result, expected);
}
