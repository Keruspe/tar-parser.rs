extern crate tar;
extern crate nom;

use tar::*;
use nom::IResult;

fn test_parse_tar(i: &[u8]) {
    match parse_tar(i) {
        IResult::Done(_, entries) => {
            for e in entries.iter() {
                println!("{:?}", e);
            }
        }
        e  => {
            println!("error or incomplete: {:?}", e);
            panic!("cannot parse tar archive");
        }
    }
}

fn main() {
    let test = include_bytes!("../test.tar");
    let long = include_bytes!("../long.tar");
    println!("parse test");
    test_parse_tar(test);
    println!("parse long");
    test_parse_tar(long);
}
