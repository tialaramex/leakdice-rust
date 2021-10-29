use anyhow::Result;

pub const PAGE_SIZE: usize = 4096;

pub struct Output {
    pub tty: Box<dyn std::io::Write>,
    pub addr_width: usize,
    pub spaces: bool,
}

const ADDR_BYTES: usize = std::mem::size_of::<usize>();
const LINE_SIZE: usize = 16;

pub fn row_diet(addr: usize) -> (usize, bool) {
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

pub fn ascii_hex(mut out: Output, addr: usize, buffer: &[u8; PAGE_SIZE]) -> Result<()> {
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

fn ascii_row(out: &mut Output, addr: usize, buffer: &[u8]) -> Result<()> {
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
fn fake_output(writer: impl std::io::Write + 'static, addr_width: usize, spaces: bool) -> Output {
    Output {
        tty: Box::new(writer),
        addr_width,
        spaces,
    }
}

#[test]
fn ar_zero() {
    let row: [u8; LINE_SIZE] = [0; LINE_SIZE];

    use std::io;
    let mut out = fake_output(io::sink(), 100, true);
    let result = ascii_row(&mut out, 0x12345678, &row);

    assert!(result.is_ok());
}

#[test]
fn ar_easy() {
    let row: [u8; LINE_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    use std::io;
    let mut out = fake_output(io::sink(), 100, true);
    let result = ascii_row(&mut out, 0x12345678, &row);

    assert!(result.is_ok());
}

#[test]
fn ar_letters() {
    let row: [u8; LINE_SIZE] = [
        64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    ];

    use std::io;
    let mut out = fake_output(io::sink(), 100, true);
    let result = ascii_row(&mut out, 0x12345678, &row);

    assert!(result.is_ok());
}

#[test]
fn ah_zero() {
    let page: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    use std::io;
    let out = fake_output(io::sink(), 100, true);
    let result = ascii_hex(out, 0x12345678, &page);

    assert!(result.is_ok());
}

#[test]
fn ah_ascending() {
    let mut page: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    for n in 0..PAGE_SIZE {
        page[n] = n as u8;
    }

    use std::io;
    let out = fake_output(io::sink(), 100, true);
    let result = ascii_hex(out, 0x12345678, &page);

    assert!(result.is_ok());
}
