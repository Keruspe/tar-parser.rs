use nom::*;
use nom::branch::alt;
use nom::bytes::complete::{tag, take, take_until};
use nom::character::complete::{oct_digit0, space0};
use nom::combinator::{all_consuming, map, map_parser, map_res, opt};
use nom::error::ErrorKind;
use nom::multi::fold_many0;
use nom::sequence::{pair, terminated};

/*
 * Core structs
 */

#[derive(Debug,PartialEq,Eq)]
pub struct TarEntry<'a> {
    pub header:   PosixHeader<'a>,
    pub contents: &'a [u8]
}

#[derive(Debug,PartialEq,Eq)]
pub struct PosixHeader<'a> {
    pub name:     &'a str,
    pub mode:     u64,
    pub uid:      u64,
    pub gid:      u64,
    pub size:     u64,
    pub mtime:    u64,
    pub chksum:   &'a str,
    pub typeflag: TypeFlag,
    pub linkname: &'a str,
    pub ustar:    ExtraHeader<'a>
}

/* TODO: support more vendor specific */
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
    GNULongName,
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
    GNULongName(GNULongNameHeader<'a>),
    Pax(PaxHeader<'a>)
}

#[derive(Debug,PartialEq,Eq)]
pub struct PosixUStarHeader<'a> {
    pub prefix: &'a str
}

#[derive(Debug,PartialEq,Eq)]
pub struct GNULongNameHeader<'a> {
    pub name: &'a str
}

#[derive(Debug,PartialEq,Eq)]
pub struct PaxHeader<'a> {
    pub atime:      u64,
    pub ctime:      u64,
    pub offset:     u64,
    pub longnames:  &'a str,
    pub sparses:    Vec<Sparse>,
    pub isextended: bool,
    pub realsize:   u64,
}

#[derive(Debug,PartialEq,Eq)]
pub struct Sparse {
    pub offset:   u64,
    pub numbytes: u64
}

#[derive(Debug,PartialEq,Eq)]
pub struct Padding;

fn parse_bool(i: &[u8]) -> IResult<&[u8], bool> {
    map(take(1usize), |i: &[u8]| i[0] != 0)(i)
}

/// Read null-terminated string and ignore the rest
fn parse_str(size: usize) -> impl FnMut(&[u8]) -> IResult<&[u8], &str> {
    move |input| {
        let s = map_res(take_until("\0"), std::str::from_utf8);
        map_parser(take(size), s)(input)
    }
}

macro_rules! impl_parse_str {
    ($($name:ident, $size:expr;)+) => ($(
        fn $name(i: &[u8]) -> IResult<&[u8], &str> {
            parse_str($size)(i)
        }
    )+)
}

impl_parse_str! {
    parse_str4, 4;
    parse_str8, 8;
    parse_str32, 32;
    parse_str100, 100;
    parse_str155, 155;
    parse_str512, 512;
}

/*
 * Octal string parsing
 */

fn parse_octal(i: &[u8], n: usize) -> IResult<&[u8], u64> {
    let (rest, input) = take(n)(i)?;
    let (i, value) = terminated(oct_digit0, space0)(input)?;

    if i.input_len() == 0 || i[0] == 0 {
        let value = value.iter().fold(0, |acc, v| acc * 8 + u64::from(*v - b'0'));
        Ok((rest, value))
    } else {
        Err(nom::Err::Error(error_position!(i, ErrorKind::OctDigit)))
    }
}

fn parse_octal8(i: &[u8]) -> IResult<&[u8], u64> {
    parse_octal(i, 8)
}

fn parse_octal12(i: &[u8]) -> IResult<&[u8], u64> {
    parse_octal(i, 12)
}

/*
 * TypeFlag parsing
 */

fn parse_type_flag(i: &[u8]) -> IResult<&[u8], TypeFlag> {
    let (c, rest) = match i.split_first() {
        Some((c, rest)) => (c, rest),
        None => return Err(nom::Err::Incomplete(Needed::new(1))),
    };
    let flag = match c {
        b'0' | b'\0'  => TypeFlag::NormalFile,
        b'1'          => TypeFlag::HardLink,
        b'2'          => TypeFlag::SymbolicLink,
        b'3'          => TypeFlag::CharacterSpecial,
        b'4'          => TypeFlag::BlockSpecial,
        b'5'          => TypeFlag::Directory,
        b'6'          => TypeFlag::FIFO,
        b'7'          => TypeFlag::ContiguousFile,
        b'g'          => TypeFlag::PaxInterexchangeFormat,
        b'x'          => TypeFlag::PaxExtendedAttributes,
        b'L'          => TypeFlag::GNULongName,
        b'A' ..= b'Z' => TypeFlag::VendorSpecific,
        _             => TypeFlag::NormalFile,
    };
    Ok((rest, flag))
}

/*
 * Sparse parsing
 */

fn parse_one_sparse(i: &[u8]) -> IResult<&[u8], Sparse> {
    let (i, (offset, numbytes)) = pair(parse_octal12, parse_octal12)(i)?;
    Ok((i, Sparse { offset, numbytes }))
}

fn parse_sparses_with_limit(i: &[u8], limit: usize) -> IResult<&[u8], Vec<Sparse>> {
    let mut res = Ok((i, Vec::new()));

    for _ in 0..limit {
        if let Ok((ref mut input, ref mut sparses)) = res {
            let (i, sp) = parse_one_sparse(input)?;
            if sp.offset == 0 && sp.numbytes == 0 {
                break;
            }
            sparses.push(sp);
            *input = i;
        } else {
            break;
        }
    }

    res
}

fn add_to_vec(sparses: &mut Vec<Sparse>, extra: Vec<Sparse>) -> &mut Vec<Sparse> {
    sparses.extend(extra);
    sparses
}

fn parse_extra_sparses<'a, 'b>(i: &'a [u8], isextended: bool, sparses: &'b mut Vec<Sparse>) -> IResult<&'a [u8], &'b mut Vec<Sparse>> {
    if isextended {
        let (i, sps) = parse_sparses_with_limit(i, 21)?;
        let (i, extended) = parse_bool(i)?;
        let (i, _) = take(7usize)(i)?; // padding to 512

        parse_extra_sparses(i, extended, add_to_vec(sparses, sps))
    } else {
        Ok((i, sparses))
    }
}

/*
 * UStar PAX extended parsing
 */

fn parse_ustar00_extra_pax(i: &[u8]) -> IResult<&[u8], PaxHeader<'_>> {
    let mut sparses = Vec::new();

    let (i, atime) = parse_octal12(i)?;
    let (i, ctime) = parse_octal12(i)?;
    let (i, offset) = parse_octal12(i)?;
    let (i, longnames) = parse_str4(i)?;
    let (i, _) = take(1usize)(i)?;
    let (i, sps) = parse_sparses_with_limit(i, 4)?;
    let (i, isextended) = parse_bool(i)?;
    let (i, realsize) = parse_octal12(i)?;
    let (i, _) = take(17usize)(i)?; // padding to 512

    let (i, _) = parse_extra_sparses(i, isextended, add_to_vec(&mut sparses, sps))?;

    let header = PaxHeader {
        atime,
        ctime,
        offset,
        longnames,
        sparses,
        isextended,
        realsize,
    };
    Ok((i, header))
}

/*
 * UStar Posix parsing
 */

fn parse_ustar00_extra_posix(i: &[u8]) -> IResult<&[u8], UStarExtraHeader<'_>> {
    let (i, prefix) = terminated(parse_str155, take(12usize))(i)?;
    let header = UStarExtraHeader::PosixUStar(PosixUStarHeader { prefix });
    Ok((i, header))
}

fn parse_ustar00_extra(i: &[u8], flag: TypeFlag) -> IResult<&[u8], UStarExtraHeader<'_>> {
    match flag {
        TypeFlag::PaxInterexchangeFormat => map(parse_ustar00_extra_pax, UStarExtraHeader::Pax)(i),
        _                                => parse_ustar00_extra_posix(i)
    }
}

fn parse_ustar00(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader<'_>> {
    let (i, _) = tag("00")(i)?;
    let (i, uname) = parse_str32(i)?;
    let (i, gname) = parse_str32(i)?;
    let (i, devmajor) = parse_octal8(i)?;
    let (i, devminor) = parse_octal8(i)?;
    let (i, extra) = parse_ustar00_extra(i, flag)?;

    let header = ExtraHeader::UStar(UStarHeader {
        magic: "ustar\0",
        version: "00",
        uname,
        gname,
        devmajor,
        devminor,
        extra,
    });
    Ok((i, header))
}

fn parse_ustar(flag: TypeFlag) -> impl FnMut(&[u8]) -> IResult<&[u8], ExtraHeader<'_>> {
    move |input| {
        let (i, _) = tag("ustar\0")(input)?;
        parse_ustar00(i, flag)
    }
}

/*
 * Posix tar archive header parsing
 */

fn parse_posix(i: &[u8]) -> IResult<&[u8], ExtraHeader<'_>> {
    map(take(255usize), |_| ExtraHeader::Padding)(i) // padding to 512
}

fn parse_maybe_longname(flag: TypeFlag) -> impl FnMut(&[u8]) -> IResult<&[u8], &str> {
    move |input| {
        match flag {
            TypeFlag::GNULongName => parse_str512(input),
            _                     => Err(nom::Err::Error(error_position!(input, ErrorKind::Complete)))
        }
    }
}

fn parse_header(i: &[u8]) -> IResult<&[u8], PosixHeader<'_>> {
    let (i, name) = parse_str100(i)?;
    let (i, mode) = parse_octal8(i)?;
    let (i, uid) = parse_octal8(i)?;
    let (i, gid) = parse_octal8(i)?;
    let (i, size) = parse_octal12(i)?;
    let (i, mtime) = parse_octal12(i)?;
    let (i, chksum) = parse_str8(i)?;
    let (i, typeflag) = parse_type_flag(i)?;
    let (i, linkname) = parse_str100(i)?;

    let (i, ustar) = alt((parse_ustar(typeflag), parse_posix))(i)?;
    let (i, longname) = opt(parse_maybe_longname(typeflag))(i)?;

    let header = PosixHeader {
        name: longname.unwrap_or(name),
        mode,
        uid,
        gid,
        size,
        mtime,
        chksum,
        typeflag,
        linkname,
        ustar,
    };
    Ok((i, header))
}

/*
 * Contents parsing
 */

fn parse_contents(i: &[u8], size: u64) -> IResult<&[u8], &[u8]> {
    let trailing = size % 512;
    let padding  = match trailing {
        0 => 0,
        t => 512 - t
    };
    terminated(take(size), take(padding))(i)
}

/*
 * Tar entry header + contents parsing
 */

fn parse_entry(i: &[u8]) -> IResult<&[u8], TarEntry<'_>> {
    let (i, header) = parse_header(i)?;
    let (i, contents) = parse_contents(i, header.size)?;
    Ok((i, TarEntry { header, contents }))
}

/*
 * Tar archive parsing
 */

pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry<'_>>> {
    let entries = fold_many0(parse_entry, Vec::new, |mut vec, e| {
        if !e.header.name.is_empty() {
            vec.push(e)
        }
        vec
    });
    all_consuming(entries)(i)
}

/*
 * Tests
 */

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind;

    const EMPTY: &[u8] = b"";

    #[test]
    fn parse_octal_ok_test() {
        assert_eq!(parse_octal(b"756", 3),       Ok((EMPTY, 494)));
        assert_eq!(parse_octal(b"756\01234", 8), Ok((EMPTY, 494)));
        assert_eq!(parse_octal(b"756    \0", 8), Ok((EMPTY, 494)));
        assert_eq!(parse_octal(b"", 0),          Ok((EMPTY, 0)));
    }

    #[test]
    fn parse_octal_error_test() {
        let t1: &[u8] = b"1238";
        let _e: &[u8] = b"8";
        let t2: &[u8] = b"a";
        let t3: &[u8] = b"A";

        assert_eq!(parse_octal(t1, 4), Err(nom::Err::Error(error_position!(_e, ErrorKind::OctDigit))));
        assert_eq!(parse_octal(t2, 1), Err(nom::Err::Error(error_position!(t2, ErrorKind::OctDigit))));
        assert_eq!(parse_octal(t3, 1), Err(nom::Err::Error(error_position!(t3, ErrorKind::OctDigit))));
    }

    #[test]
    fn parse_str_test() {
        let s: &[u8]   = b"foobar\0\0\0\0baz";
        let baz: &[u8] = b"baz";
        assert_eq!(parse_str(10)(s), Ok((baz, "foobar")));
    }
}
