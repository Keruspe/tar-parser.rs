#![feature(plugin)]
#![plugin(afl_coverage_plugin)]

extern crate afl_coverage;
extern crate tar;
extern crate nom;

use tar::*;
use nom::IResult;
use std::fs::File;
use std::io::{self, Read};

fn main() {
    let mut contents: Vec<u8> = Vec::new();
    let result = io::stdin().read_to_end(&mut contents).unwrap();
    let tar = &contents[..];

    match parse_tar(tar) {
        IResult::Done(_, entries) => {
            for e in entries.iter() {
                //println!("{:?}", e);
            }
        }
        e  => {
            //println!("error or incomplete: {:?}", e);
            //panic!("cannot parse tar archive");
        }
    }
}
