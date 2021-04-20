use std::env;
use std::ffi::OsString;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::Result;

#[derive(Debug,PartialEq,Eq)]
pub struct Settings {
    pub name: String,
    pub pid: Option<u32>,
    pub addr: Option<u64>,
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

    let pid = arg_to_int::<u32>(args.next())?;

    let addr = arg_to_int::<u64>(args.next())?;

    Ok(Settings { name, pid, addr })
}

fn arg_to_int<F>(s: Option<OsString>) -> Result<Option<F>> where
    F: FromStr, <F as FromStr>::Err: std::error::Error, <F as FromStr>::Err: Send, <F as FromStr>::Err: Sync, <F as FromStr>::Err: 'static {

    let arg = match s {
        None => return Ok(None),
        Some(s) => s,
    };

    let z = arg.into_string();

    let arg = match z {
        Ok(s) => s,
        Err(_) => return Err(anyhow!("Ugh")),
    };

    let num = arg.parse::<F>()?;

    Ok(Some(num))
}


use std::fs::File;

pub fn doit(settings: Settings) {
    let procfile = format!("/proc/{}/mem", settings.pid.expect("Shouldn't call this without setting pid"));

    println!("procfile={}", procfile);

    let fd = File::open(procfile).unwrap();

    fd.sync_all().unwrap();
}

#[cfg(test)]
#[test]
fn ati_none() {
    let result = arg_to_int::<u32>(None);
    let inner = result.expect("tried to parse empty argument");

    assert_eq!(inner, None);
}

#[test]
#[should_panic(expected = "Not a number")]
fn ati_space() {
    let space = Some(OsString::from(" "));

    let result = arg_to_int::<u32>(space);
    let _ = result.expect("Not a number");
}

#[test]
fn ati_five() {
    let five = Some(OsString::from("5"));

    let result = arg_to_int::<u32>(five);
    let inner = result.expect("unable to parse five");

    assert_eq!(inner, Some(5));
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
fn rai_example() {
    let name = "program_name".to_string();
    let expected = Settings { name, pid: Some(1234), addr: None };
    let mut example: Vec<OsString> = Vec::new();

    example.push(OsString::from("program_name"));
    example.push(OsString::from("1234"));

    let result = read_args_internal(example.iter().cloned()).unwrap();

    assert_eq!(result, expected);
}
