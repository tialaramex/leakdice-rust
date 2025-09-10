# Leakdice

leakdice is a tool which dumps random pages from a specified process

## Dependencies

Linux 2.x or better with proc filesystem

## Idea

leakdice is useful when for some reason a methodical approach to identifying memory leaks isn't available
e.g. because the process is already running and it's too late to instrument it.
leakdice was inspired in part by Raymond Chen's blog article
[The poor man's way of identifying memory leaks](https://devblogs.microsoft.com/oldnewthing/20050815-11/?p=34583)

## Concept

The idea behind leakdice is that a Monte Carlo sampling method is effective
for diagnosing gross leaks. Unlike more conventional leak-detecting methods
the sampling method doesn't require the process to be instrumented, instead
it relies on the following chain of ideas:

* The program's normal working set is much smaller than the leaked data

* Therefore a randomly selected page of heap data is much more likely to
contain leaked data than other (not leaked) data

* Low-level programmers most likely to be diagnosing a leak are familiar
enough with the data structures used in their code that there's a good chance
they can identify them by sight

## Usage

For example, if your leaking process has PID 5844, simply type:

## leakdice 5844

If the page dumped seems irrelevant, try again, a different random page
should be chosen.

## Source

leakdice was developed by Nick Lamb.
You are welcome to modify, copy and redistribute this software under the terms
of the GNU GPL which is included in the file COPYING.
