use std::process;
use leakdice_rust::read_args;

use std::fs::File;

fn main() {
    let settings = read_args().unwrap_or_else(|err| {
        eprintln!("Trouble parsing the arguments: {}", err);
        process::exit(1);
    });

    let pid = settings.pid.unwrap_or_else(|| {
        eprintln!("{} <pid> [addr] dump some heap pages from a process to diagnose leaks", settings.name);
        process::exit(0);
    });

    let procfile = format!("/proc/{}/mem", pid);

    println!("procfile={}", procfile);
        
    let fd = File::open(procfile).unwrap();

    fd.sync_all().unwrap();

}

