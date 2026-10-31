//! demo-report <run-dir>

use std::path::Path;
use std::process::exit;

use demo_report::{Inputs, render};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 2 {
        eprintln!("usage: demo-report <run-dir>");
        exit(2);
    }
    let run = Path::new(&a[1]);
    print!("{}", render(&a[1], &Inputs::read(run)));
}
