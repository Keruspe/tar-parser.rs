use std::str::from_utf8;
use nom::IResult;

#[derive(Debug,PartialEq,Eq)]
pub struct PosixHeader<'a> {
    pub name:     & 'a str,
    pub mode:     & 'a str,
    pub uid:      u64,
    pub gid:      u64,
    pub size:     u64,
    pub mtime:    u64,
    pub chksum:   & 'a str,
    pub typeflag: TypeFlag,
    pub linkname: & 'a str,
    pub ustar:    Option<UStarHeader<'a>>
}

#[derive(Debug,PartialEq,Eq)]
pub struct UStarHeader<'a> {
    pub magic:    & 'a str,
    pub version:  & 'a str,
    pub uname:    & 'a str,
    pub gname:    & 'a str,
    pub devmajor: u64,
    pub devminor: u64,
    pub prefix:   & 'a str,
}

#[derive(Debug,PartialEq,Eq)]
pub struct TarEntry<'a> {
    pub header:   PosixHeader<'a>,
    pub contents: & 'a str
}

/* TODO: support vendor specific + sparse */
#[derive(Debug,PartialEq,Eq)]
pub enum TypeFlag {
    NormalFile,
    HardLink,
    SymbolicLink,
    CharacterSpecial,
    BlockSpecial,
    Directory,
    FIFO,
    ContiguousFile,
    GlobalExtendedHeaderWithMetadata,
    ExtendedHeaderWithMetadataForNext,
    VendorSpecific,
    Invalid
}

/* TODO: validation */
fn str_to_u64(s: &str, base: u64) -> u64 {
    let mut u = 0;
    let mut f = 1;

    for c in s.chars().rev().skip_while(|&c| c == '\0') {
        u += f * ((c as u64) - ('0' as u64));
        f *= base;
    }

    u
}

pub fn octal_to_u64(o: &str) -> u64 {
    str_to_u64(o, 8)
}

fn char_to_type_flag(c: char) -> TypeFlag {
    match c {
        '0' | '\0' => TypeFlag::NormalFile,
        '1' => TypeFlag::HardLink,
        '2' => TypeFlag::SymbolicLink,
        '3' => TypeFlag::CharacterSpecial,
        '4' => TypeFlag::BlockSpecial,
        '5' => TypeFlag::Directory,
        '6' => TypeFlag::FIFO,
        '7' => TypeFlag::ContiguousFile,
        'g' => TypeFlag::GlobalExtendedHeaderWithMetadata,
        'x' => TypeFlag::ExtendedHeaderWithMetadataForNext,
        'A' ... 'Z' => TypeFlag::VendorSpecific,
        _ => TypeFlag::Invalid
    }
}

fn parse_ustar00(i: &[u8]) -> IResult<&[u8], Option<UStarHeader>> {
    chain!(i,
        tag!("00")               ~
        uname:    take_str!(32)  ~
        gname:    take_str!(32)  ~
        devmajor: take_str!(8)   ~
        devminor: take_str!(8)   ~
        prefix:   take_str!(155) ~
        take!(12), /* padding to 512 */
        ||{
            Some(UStarHeader {
                magic:    "ustar\0",
                version:  "00",
                uname:    uname,
                gname:    gname,
                devmajor: octal_to_u64(devmajor),
                devminor: octal_to_u64(devminor),
                prefix:   prefix
            })
        }
    )
}

fn parse_ustar(i: &[u8]) -> IResult<&[u8], Option<UStarHeader>> {
    chain!(i,
        tag!("ustar\0") ~
        ustar: parse_ustar00,
        ||{
            ustar
        }
    )
}

fn parse_posix(i: &[u8]) -> IResult<&[u8], Option<UStarHeader>> {
    chain!(i,
        take!(255), /* padding to 512 */
        ||{
            None
        }
    )
}

fn parse_header(i: &[u8]) -> IResult<&[u8], PosixHeader> {
    chain!(i,
        name:     take_str!(100) ~
        mode:     take_str!(8)   ~
        uid:      take_str!(8)   ~
        gid:      take_str!(8)   ~
        size:     take_str!(12)  ~
        mtime:    take_str!(12)  ~
        chksum:   take_str!(8)   ~
        typeflag: take!(1)       ~
        linkname: take_str!(100) ~
        ustar:    alt!(parse_ustar | parse_posix),
        ||{
            PosixHeader {
                name:     name,
                mode:     mode,
                uid:      octal_to_u64(uid),
                gid:      octal_to_u64(gid),
                size:     octal_to_u64(size),
                mtime:    octal_to_u64(mtime),
                chksum:   chksum,
                typeflag: char_to_type_flag(typeflag[0] as char),
                linkname: linkname,
                ustar:    ustar
            }
        }
    )
}

fn parse_contents(i: &[u8], size: u64) -> IResult<&[u8], &str> {
    let trailing = size % 512;
    let padding = match trailing {
        0 => 0,
        t => 512 - t
    };
    chain!(i,
        contents: take_str!(size as usize) ~
        take!(padding as usize),
        ||{
            contents
        }
    )
}

fn parse_entry(i: &[u8]) -> IResult<&[u8], TarEntry> {
    chain!(i,
        header:   parse_header ~
        contents: apply!(parse_contents, header.size),
        ||{
            TarEntry {
                header: header,
                contents: contents
            }
        }
    )
}

pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry>> {
    many0!(i, parse_entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_to_u64_test() {
        match octal_to_u64("756") {
            494 => {},
            o => panic!("octal_to_u64 failed, expected 494 but got {}", o)
        }
        match octal_to_u64("") {
            0 => {},
            o => panic!("octal_to_u64 failed, expected 0 but got {}", o)
        }
    }
}
