use anyhow::anyhow;
use anyhow::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Memory {
    pub start: usize,
    pub pages: usize,
    pub perms: MemoryPermissions,
    pub offset: usize,
}

use crate::PAGE_SIZE;

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

pub fn memory_map<L>(lines: L) -> Result<Vec<Memory>>
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
mod tests {

    use super::*;

    #[test]
    fn mtoc_z() {
        let re = regex::Regex::new("(.)").unwrap();
        let cap = re.captures("z").unwrap();

        let z = match_to_one_char(cap.get(1).unwrap());

        assert_eq!(z, 'z');
    }

    #[test]
    fn construct() {
        let _mem = Memory::new(0x01234000, 0x09876000, 'r', 'w', 'x', 'p', 0x0ffff000);
    }

    fn fake_file() -> Vec<std::io::Result<String>> {
        let mut v = Vec::<std::io::Result<String>>::with_capacity(4);
        let s1 = "12345000-13450000 rw-p 00000000 00:00 0".to_owned();
        let s2 = "20100000-20200000 rw-p 00000000 00:00 0".to_owned();
        let s3 = "34568000-45678000 rw-p 00000000 00:00 0".to_owned();
        let s4 = "e0111000-e0222000 rw-p 00000000 00:00 0".to_owned();
        v.push(Ok(s1));
        v.push(Ok(s2));
        v.push(Ok(s3));
        v.push(Ok(s4));
        v
    }

    #[test]
    fn fake_maps() {
        let lines = fake_file();
        let mem = memory_map(lines.into_iter()).unwrap();

        const RW_P: MemoryPermissions = MemoryPermissions {
            read: true,
            write: true,
            execute: false,
            shared: false,
        };

        assert_eq!(mem.len(), 4);
        for m in mem {
            assert_eq!(m.perms, RW_P);
        }
    }
}
