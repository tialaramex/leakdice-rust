use std::process;
use leakdice_rust::read_args;
use leakdice_rust::doit;

fn main() {
    let settings = read_args().unwrap_or_else(|err| {
        eprintln!("Trouble parsing the arguments: {}", err);
        process::exit(1);
    });

    if settings.pid == None {
        eprintln!("{} <pid> [addr] dump some heap pages from a process to diagnose leaks", settings.name);
        process::exit(0);
    };

    doit(settings);
}

