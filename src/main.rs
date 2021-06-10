/*  leakdice - Monte Carlo sampling of heap data

    Copyright (C) 2009-21 Nick Lamb

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* This is useful when for some reason a methodical approach to identifying memory leaks isn't available
 * e.g. because the process is already running and it's too late to instrument it
 * it's inspired in part by Raymond Chen's blog article "The poor man's way of identifying memory leaks" */


use leakdice_rust::doit;
use leakdice_rust::read_args;
use std::process;

fn main() {
    let settings = read_args().unwrap_or_else(|err| {
        eprintln!("Trouble parsing the arguments: {}", err);
        process::exit(1);
    });

    if settings.pid == None {
        eprintln!(
            "{} <pid> [addr] dump some heap pages from a process to diagnose leaks",
            settings.name
        );
        process::exit(0);
    };

    match doit(settings) {
        Err(x) => eprintln!("Trouble: {}", x),
        _ => (),
    }
}
