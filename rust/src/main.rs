extern crate clap;
use clap::{App, Arg};
use std::fs::File;
use std::io::prelude::*;
use std::{io, u8};

fn main() -> io::Result<()> {
    let matches = App::new("LdpInch Unpacker")
        .version("1.0.0")
        .about("Unpack LdpInch malware.")
        .arg(
            Arg::with_name("input")
                .short("i")
                .help("LdpInch file to unpack.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .help("Unpacked output file.")
                .default_value("unpacked.bin"),
        )
        .get_matches();

    let input = match matches.value_of("input") {
        Some(s) => s,
        None => panic!("No input give."),
    };

    let output = match matches.value_of("output") {
        Some(s) => s,
        None => panic!("No output given."),
    };

    let mut buffer = read_binary(input)?;
    unpack(0x480, 0x1773, &mut buffer);
    write_binary(output, &mut buffer)
}

fn read_binary(file: &str) -> io::Result<Vec<u8>> {
    let mut f = File::open(file)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn write_binary(file: &str, buffer: &Vec<u8>) -> io::Result<()> {
    let mut f = File::create(file)?;
    f.write_all(buffer)?;
    Ok(())
}

fn unpack(start: usize, end: usize, buffer: &mut Vec<u8>) -> () {
    for i in start..end + 1 {
        buffer[i] ^= 0x89;
    }

    buffer[start] ^= 0x9f;
    let mut key = 0x54;
    for i in start + 1..end + 1 {
        buffer[i] ^= key;
        key = key.wrapping_add(0x12); // key += 0x12; Leads to overflow
        key ^= 0x68;
        key = key.wrapping_sub(0x04); // key -= 0x04; Leads to underflow
    }
}
