#![feature(plugin)]
#![plugin(afl_plugin)]

extern crate afl;
extern crate tar;
extern crate nom;

use tar::*;
use nom::IResult;
use std::io::{self, Read};

fn main() {
    let mut contents: Vec<u8> = Vec::new();
    io::stdin().read_to_end(&mut contents).unwrap();
    let tar = &contents[..];

    match parse_tar(tar) {
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
