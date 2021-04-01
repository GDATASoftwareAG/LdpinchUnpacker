extern crate clap;
use clap::{App, Arg};
use std::fs::File;
use std::io::prelude::*;
use std::{io, u8};

fn main() -> io::Result<()> {
    let matches = App::new("LdpInch Unpacker")
        .version("1.0.1")
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
                .help("Unpacked output file."),
        )
        .get_matches();

    let input = matches.value_of("input").unwrap();
    let output = matches.value_of("output").unwrap_or("unpacked.bin");

    let mut buffer = read_binary(input)?;
    unpack(0x480, 0x1773, &mut buffer);
    write_binary(output, &mut buffer)
}

fn read_binary(file: &str) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    File::open(file)?.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn write_binary(file: &str, buffer: &Vec<u8>) -> io::Result<()> {
    File::create(file)?.write_all(buffer)
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
