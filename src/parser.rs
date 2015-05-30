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
    pub typeflag: char, /* TODO: enum */
    pub linkname: & 'a str,
    pub ustar:    Option<UStarHeader<'a>>
}

#[derive(Debug,PartialEq,Eq)]
pub struct UStarHeader<'a> {
    pub magic:    & 'a str,
    pub version:  & 'a str,
    pub uname:    & 'a str,
    pub gname:    & 'a str,
    pub devmajor: & 'a str,
    pub devminor: & 'a str,
    pub prefix:   & 'a str,
}

#[derive(Debug,PartialEq,Eq)]
pub struct TarEntry<'a> {
    pub header:   PosixHeader<'a>,
    pub contents: & 'a str
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

pub fn decimal_to_u64(d: &str) -> u64 {
    str_to_u64(d, 10)
}

fn parse_ustar(i: &[u8]) -> IResult<&[u8], Option<UStarHeader>> {
    chain!(i,
        magic:    map_res!(take!(6),   from_utf8) ~
        version:  map_res!(take!(2),   from_utf8) ~
        uname:    map_res!(take!(32),  from_utf8) ~
        gname:    map_res!(take!(32),  from_utf8) ~
        devmajor: map_res!(take!(8),   from_utf8) ~
        devminor: map_res!(take!(8),   from_utf8) ~
        prefix:   map_res!(take!(155), from_utf8),
        ||{
            match magic {
                "ustar" => Some(UStarHeader {
                    magic:    magic,
                    version:  version,
                    uname:    uname,
                    gname:    gname,
                    devmajor: devmajor,
                    devminor: devminor,
                    prefix:   prefix
                }),
                _ => None,
            }
        }
    )
}

fn parse_header(i: &[u8]) -> IResult<&[u8], PosixHeader> {
    chain!(i,
        name:     map_res!(take!(100), from_utf8) ~
        mode:     map_res!(take!(8),   from_utf8) ~
        uid:      map_res!(take!(8),   from_utf8) ~
        gid:      map_res!(take!(8),   from_utf8) ~
        size:     map_res!(take!(12),  from_utf8) ~
        mtime:    map_res!(take!(12),  from_utf8) ~
        chksum:   map_res!(take!(8),   from_utf8) ~
        typeflag: take!(1)                        ~
        linkname: map_res!(take!(100), from_utf8) ~
        ustar:    parse_ustar                     ~
        take!(12), /* padding to 512 */
        ||{
            PosixHeader {
                name:     name,
                mode:     mode,
                uid:      decimal_to_u64(uid),
                gid:      decimal_to_u64(gid),
                size:     octal_to_u64(size),
                mtime:    octal_to_u64(mtime), /* TODO: u64 */
                chksum:   chksum,
                typeflag: typeflag[0] as char,
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
        contents: map_res!(take!(size as usize), from_utf8) ~
        take!(padding as usize),
        ||{
            contents
        }
    )
}

macro_rules! apply (
 ($i:expr, $fun:expr, $arg:expr ) => ( $fun( $i, $arg ) );
);

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
    fn octal_to_u32_test() {
        match octal_to_u32("756") {
            494 => {},
            o => panic!("octal_to_u32 failed, expected 494 but got {}", o)
        }
        match octal_to_u32("") {
            0 => {},
            o => panic!("octal_to_u32 failed, expected 0 but got {}", o)
        }
    }

    #[test]
    fn decimal_to_u32_test() {
        match decimal_to_u32("756") {
            756 => {},
            d => panic!("decimal_to_u32 failed, expected 756 but got {}", d)
        }
        match decimal_to_u32("") {
            0 => {},
            d => panic!("decimal_to_u32 failed, expected 0 but got {}", d)
        }
    }
}
