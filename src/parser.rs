use std::str::from_utf8;
use std::result::Result;
use nom::IResult;

#[derive(Debug,PartialEq,Eq)]
pub struct TarEntry<'a> {
    pub header:   PosixHeader<'a>,
    pub contents: &'a str
}

#[derive(Debug,PartialEq,Eq)]
pub struct PosixHeader<'a> {
    pub name:     &'a str,
    pub mode:     &'a str,
    pub uid:      u64,
    pub gid:      u64,
    pub size:     u64,
    pub mtime:    u64,
    pub chksum:   &'a str,
    pub typeflag: TypeFlag,
    pub linkname: &'a str,
    pub ustar:    ExtraHeader<'a>
}

/* TODO: support vendor specific + sparse */
#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum TypeFlag {
    NormalFile,
    HardLink,
    SymbolicLink,
    CharacterSpecial,
    BlockSpecial,
    Directory,
    FIFO,
    ContiguousFile,
    PaxInterexchangeFormat,
    PaxExtendedAttributes,
    VendorSpecific
}

#[derive(Debug,PartialEq,Eq)]
pub enum ExtraHeader<'a> {
    UStar(UStarHeader<'a>),
    Padding
}

#[derive(Debug,PartialEq,Eq)]
pub struct UStarHeader<'a> {
    pub magic:    &'a str,
    pub version:  &'a str,
    pub uname:    &'a str,
    pub gname:    &'a str,
    pub devmajor: u64,
    pub devminor: u64,
    pub extra:    UStarExtraHeader<'a>
}

#[derive(Debug,PartialEq,Eq)]
pub enum UStarExtraHeader<'a> {
    PosixUStar(PosixUStarHeader<'a>),
    Pax(PaxHeader<'a>)
}

#[derive(Debug,PartialEq,Eq)]
pub struct PosixUStarHeader<'a> {
    pub prefix: &'a str
}

#[derive(Debug,PartialEq,Eq)]
pub struct PaxHeader<'a> {
    pub atime:      u64,
    pub ctime:      u64,
    pub offset:     u64,
    pub longnames:  &'a str,
    pub sparse:     [Sparse; 4],
    pub isextended: bool,
    pub realsize:   u64
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub struct Sparse {
    pub offset:   u64,
    pub numbytes: u64
}

#[derive(Debug,PartialEq,Eq)]
pub struct Padding;

pub fn octal_to_u64(s: &str) -> Result<u64, &'static str> {
    let mut u = 0;

    for c in s.chars() {
        if c < '0' || c > '7' {
            return Err("invalid octal string received");
        }
        u *= 8;
        u += (c as u64) - ('0' as u64);
    }

    Ok(u)
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
        'g' => TypeFlag::PaxInterexchangeFormat,
        'x' => TypeFlag::PaxExtendedAttributes,
        'A' ... 'Z' => TypeFlag::VendorSpecific,
        _ => TypeFlag::NormalFile
    }
}

fn parse_type_flag(i: &[u8]) -> Result<TypeFlag, &'static str> {
    Ok(char_to_type_flag(i[0] as char))
}

macro_rules! take_str_eat_garbage (
 ( $i:expr, $size:expr ) => ( chain!( $i, s: map_res!(take_until!("\0"), from_utf8) ~ take!($size - s.len()), ||{ s } ));
);

fn parse_one_sparse(i: &[u8]) -> IResult<&[u8], Sparse> {
    chain!(i,
        offset:   map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        numbytes: map_res!(take_str_eat_garbage!(12), octal_to_u64),
        ||{
            Sparse {
                offset:   offset,
                numbytes: numbytes
            }
        }
    )
}

fn parse_sparse(i: &[u8]) -> IResult<&[u8], [Sparse; 4]> {
    count!(i, parse_one_sparse, Sparse, 4)
}

fn to_bool(i: &[u8]) -> Result<bool, &'static str> {
    Ok(i[0] != 0)
}

fn parse_ustar00_extra_pax(i: &[u8]) -> IResult<&[u8], UStarExtraHeader> {
    chain!(i,
        atime:      map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        ctime:      map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        offset:     map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        longnames:  take_str_eat_garbage!(4)                          ~
        take!(1)                                                      ~
        sparse:     parse_sparse                                      ~
        isextended: map_res!(take!(1), to_bool)                       ~
        realsize:   map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        take!(17), /* padding to 512 */
        ||{
            UStarExtraHeader::Pax(PaxHeader {
                atime:      atime,
                ctime:      ctime,
                offset:     offset,
                longnames:  longnames,
                sparse:     sparse,
                isextended: isextended,
                realsize:   realsize
            })
        }
    )
}

fn parse_ustar00_extra_posix(i: &[u8]) -> IResult<&[u8], UStarExtraHeader> {
    chain!(i,
        prefix: take_str_eat_garbage!(155) ~
        take!(12),
        ||{
            UStarExtraHeader::PosixUStar(PosixUStarHeader {
                prefix: prefix
            })
        }
    )
}

fn parse_ustar00_extra(i: &[u8], flag: TypeFlag) -> IResult<&[u8], UStarExtraHeader> {
    match flag {
        TypeFlag::PaxInterexchangeFormat => parse_ustar00_extra_pax(i),
        _ => parse_ustar00_extra_posix(i)
    }
}

fn parse_ustar00(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader> {
    chain!(i,
        tag!("00")                                                 ~
        uname:    take_str_eat_garbage!(32)                        ~
        gname:    take_str_eat_garbage!(32)                        ~
        devmajor: map_res!(take_str_eat_garbage!(8), octal_to_u64) ~
        devminor: map_res!(take_str_eat_garbage!(8), octal_to_u64) ~
        extra:    apply!(parse_ustar00_extra, flag),
        ||{
            ExtraHeader::UStar(UStarHeader {
                magic:    "ustar\0",
                version:  "00",
                uname:    uname,
                gname:    gname,
                devmajor: devmajor,
                devminor: devminor,
                extra:    extra
            })
        }
    )
}

fn parse_ustar(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader> {
    chain!(i,
        tag!("ustar\0") ~
        ustar: apply!(parse_ustar00, flag),
        ||{
            ustar
        }
    )
}

fn parse_posix(i: &[u8]) -> IResult<&[u8], ExtraHeader> {
    chain!(i,
        take!(255), /* padding to 512 */
        ||{
            ExtraHeader::Padding
        }
    )
}

fn parse_header(i: &[u8]) -> IResult<&[u8], PosixHeader> {
    chain!(i,
        name:     take_str_eat_garbage!(100)                        ~
        mode:     take_str_eat_garbage!(8)                          ~
        uid:      map_res!(take_str_eat_garbage!(8),  octal_to_u64) ~
        gid:      map_res!(take_str_eat_garbage!(8),  octal_to_u64) ~
        size:     map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        mtime:    map_res!(take_str_eat_garbage!(12), octal_to_u64) ~
        chksum:   take_str_eat_garbage!(8)                          ~
        typeflag: map_res!(take!(1), parse_type_flag)               ~
        linkname: take_str_eat_garbage!(100)                        ~
        ustar:    alt!(apply!(parse_ustar, typeflag) | parse_posix),
        ||{
            PosixHeader {
                name:     name,
                mode:     mode,
                uid:      uid,
                gid:      gid,
                size:     size,
                mtime:    mtime,
                chksum:   chksum,
                typeflag: typeflag,
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

fn filter_entries(entries: Vec<TarEntry>) -> Result<Vec<TarEntry>, &'static str> {
    Ok(entries.into_iter().filter(|e| e.header.name != "").collect::<Vec<TarEntry>>())
}

// TODO: eof
pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry>> {
    map_res!(i, many0!(parse_entry), filter_entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::from_utf8;
    use nom::IResult;

    #[test]
    fn octal_to_u64_ok_test() {
        assert_eq!(octal_to_u64("756"), Ok(494));
        assert_eq!(octal_to_u64(""), Ok(0));
    }

    #[test]
    fn octal_to_u64_error_test() {
        assert_eq!(octal_to_u64("1238"), Err("invalid octal string received"));
        assert_eq!(octal_to_u64("a"), Err("invalid octal string received"));
        assert_eq!(octal_to_u64("A"), Err("invalid octal string received"));
    }

    #[test]
    fn take_str_eat_garbage_test() {
        let s = b"foobar\0\0\0\0baz";
        let baz = b"baz";
        assert_eq!(take_str_eat_garbage!(&s[..], 10), IResult::Done(&baz[..], "foobar"));
    }
}
