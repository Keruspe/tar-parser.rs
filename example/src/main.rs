extern crate tar;
extern crate nom;

use tar::*;
use nom::IResult;

fn main() {
    let tar = include_bytes!("../test.tar");
    match parse_tar(tar) {
        IResult::Done(_, entries) => {
            for e in entries.iter() {
                println!("{}", e.header.name)
            }
        }
        e  => {
            println!("error or incomplete: {:?}", e);
            panic!("cannot parse tar archive");
        }
    }
}
