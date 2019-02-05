extern crate tar;

use tar::*;

fn test_parse_tar(i: &[u8]) {
    match parse_tar(i) {
        Ok((_, entries)) => {
            for e in entries.iter() {
                println!("{:?}", e);
            }
        }
        Err(e)  => {
            println!("error or incomplete: {:?}", e);
            panic!("cannot parse tar archive");
        }
    }
}

fn main() {
    let test = include_bytes!("../test.tar");
    let macos = include_bytes!("../macos.tar");
    let long = include_bytes!("../long.tar");
    println!("parse test");
    test_parse_tar(test);
    println!("parse macos");
    test_parse_tar(macos);
    println!("parse long");
    test_parse_tar(long);
}
