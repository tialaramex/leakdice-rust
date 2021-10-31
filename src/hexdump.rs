use anyhow::Result;

pub const PAGE_SIZE: usize = 4096;
pub const LINE_SIZE: usize = 16;

pub struct Output<'t> {
    pub tty: Box<dyn std::io::Write + 't>,
    pub addr_width: usize,
    pub spaces: bool,
}

impl<'t> Output<'t> {
    pub fn new(writer: impl std::io::Write + 't, addr_width: usize, spaces: bool) -> Output<'t> {
        Output {
            tty: Box::new(writer),
            addr_width,
            spaces,
        }
    }
}

pub fn ascii_page(mut out: Output<'_>, addr: usize, buffer: &[u8; PAGE_SIZE]) -> Result<()> {
    let mut old_slice = &buffer[..0];
    let mut repeat = false;
    for line in 0..(PAGE_SIZE / LINE_SIZE) {
        let offset = line * LINE_SIZE;
        let slice = &buffer[offset..(offset + LINE_SIZE)];
        if slice != old_slice {
            ascii_row(&mut out, addr + offset, slice)?;
            repeat = false;
        } else if !repeat {
            write!(*out.tty, " ...\n")?;
            repeat = true;
        }
        old_slice = slice;
    }
    Ok(())
}

fn ascii_row(out: &mut Output<'_>, addr: usize, buffer: &[u8]) -> Result<()> {
    write!(
        *out.tty,
        "{addr:0size$x} ",
        size = out.addr_width,
        addr = addr
    )?;
    for byte in buffer {
        if *byte > 31 && *byte < 127 {
            write!(*out.tty, "{}", (*byte as char))?;
        } else {
            write!(*out.tty, ".")?;
        }
    }
    if out.spaces {
        for byte in buffer {
            write!(*out.tty, " {:02x}", byte)?;
        }
    } else {
        write!(*out.tty, " ")?;
        for byte in buffer {
            write!(*out.tty, "{:02x}", byte)?;
        }
    }
    write!(*out.tty, "\n")?;

    Ok(())
}

#[cfg(test)]
#[test]
fn ar_zero() {
    let row: [u8; LINE_SIZE] = [0; LINE_SIZE];
    let mut bytes: Vec<u8> = Vec::new();

    {
        let mut out = Output::new(&mut bytes, 16, true);
        let result = ascii_row(&mut out, 0x12345678, &row);
        assert!(result.is_ok());
    }
    let ideal =
        "0000000012345678 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n";
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, ideal);
}

#[test]
fn ar_easy() {
    let row: [u8; LINE_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut bytes: Vec<u8> = Vec::new();

    {
        let mut out = Output::new(&mut bytes, 16, false);
        let result = ascii_row(&mut out, 0x12345678, &row);
        assert!(result.is_ok());
    }
    let ideal = "0000000012345678 ................ 000102030405060708090a0b0c0d0e0f\n";
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, ideal);
}

#[test]
fn ar_letters() {
    let row: [u8; LINE_SIZE] = [
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    ];
    let mut bytes: Vec<u8> = Vec::new();

    {
        let mut out = Output::new(&mut bytes, 12, true);
        let result = ascii_row(&mut out, 0x12345678, &row);
        assert!(result.is_ok());
    }
    let ideal = "000012345678 @ABCDEFGHIJKLMNO 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f\n";
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, ideal);
}

#[test]
fn ah_zero() {
    let page: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
    let mut bytes: Vec<u8> = Vec::new();

    {
        let out = Output::new(&mut bytes, 12, true);
        let result = ascii_page(out, 0x9876543210, &page);
        assert!(result.is_ok());
    }
    let ideal =
        "009876543210 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n ...\n";
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text, ideal);
}

#[test]
fn ah_ascending() {
    let mut page: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    for n in 0..PAGE_SIZE {
        page[n] = n as u8;
    }
    let mut bytes: Vec<u8> = Vec::new();

    {
        let out = Output::new(&mut bytes, 12, true);
        let result = ascii_page(out, 0x12345678, &page);
        assert!(result.is_ok());
    }
    let text = String::from_utf8(bytes).unwrap();
    assert_eq!(text.len(), 19968);
}
