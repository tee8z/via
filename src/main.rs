use std::{env::args_os, process::ExitCode};
use via::run;

fn main() -> ExitCode {
    run(args_os())
}
