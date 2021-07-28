use nom::*;
use nom::bytes::complete::{take, take_until};
use nom::character::complete::{oct_digit0, space0};
use nom::combinator::{map_parser, map_res};
use nom::error::ErrorKind;
use nom::sequence::terminated;

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

/*
 * Useful macros
 */

named!(parse_bool<&[u8], bool>, map!(take!(1), |i: &[u8]| i[0] != 0));

macro_rules! take_str_eat_garbage (
    ( $i:expr, $size:expr ) => ({
        parse_str($size)($i)
    });
);

/// Read null-terminated string and ignore the rest
fn parse_str(size: usize) -> impl FnMut(&[u8]) -> IResult<&[u8], &str> {
    move |input| {
        let s = map_res(take_until("\0"), std::str::from_utf8);
        map_parser(take(size), s)(input)
    }
}

named!(parse_str4<&[u8], &str>,   take_str_eat_garbage!(4));
named!(parse_str8<&[u8], &str>,   take_str_eat_garbage!(8));
named!(parse_str32<&[u8], &str>,  take_str_eat_garbage!(32));
named!(parse_str100<&[u8], &str>, take_str_eat_garbage!(100));
named!(parse_str155<&[u8], &str>, take_str_eat_garbage!(155));
named!(parse_str512<&[u8], &str>, take_str_eat_garbage!(512));

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

named!(parse_octal8<&[u8], u64>,  call!(parse_octal, 8));
named!(parse_octal12<&[u8], u64>, call!(parse_octal, 12));

/*
 * TypeFlag parsing
 */

fn char_to_type_flag(c: char) -> TypeFlag {
    match c {
        '0' | '\0'  => TypeFlag::NormalFile,
        '1'         => TypeFlag::HardLink,
        '2'         => TypeFlag::SymbolicLink,
        '3'         => TypeFlag::CharacterSpecial,
        '4'         => TypeFlag::BlockSpecial,
        '5'         => TypeFlag::Directory,
        '6'         => TypeFlag::FIFO,
        '7'         => TypeFlag::ContiguousFile,
        'g'         => TypeFlag::PaxInterexchangeFormat,
        'x'         => TypeFlag::PaxExtendedAttributes,
        'L'         => TypeFlag::GNULongName,
        'A' ..= 'Z' => TypeFlag::VendorSpecific,
        _           => TypeFlag::NormalFile
    }
}

fn bytes_to_type_flag(i: &[u8]) -> TypeFlag {
    char_to_type_flag(i[0] as char)
}

named!(parse_type_flag<&[u8], TypeFlag>, map!(take!(1), bytes_to_type_flag));

/*
 * Sparse parsing
 */

named!(parse_one_sparse<&[u8], Sparse>, do_parse!(offset: parse_octal12 >> numbytes: parse_octal12 >> (Sparse { offset: offset, numbytes: numbytes })));

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
        do_parse!(i,
            sps:           call!(parse_sparses_with_limit, 21)                             >>
            extended:      parse_bool                                                      >>
            take!(7) /* padding to 512 */                                                  >>
            extra_sparses: call!(parse_extra_sparses, extended, add_to_vec(sparses, sps))  >>
            (extra_sparses)
        )
    } else {
        Ok((i, sparses))
    }
}

/*
 * UStar PAX extended parsing
 */

fn parse_ustar00_extra_pax(i: &[u8]) -> IResult<&[u8], PaxHeader<'_>> {
    let mut sparses = Vec::new();

    do_parse!(i,
        atime:      parse_octal12                                              >>
        ctime:      parse_octal12                                              >>
        offset:     parse_octal12                                              >>
        longnames:  parse_str4                                                 >>
        take!(1)                                                               >>
        sps:        call!(parse_sparses_with_limit, 4)                         >>
        isextended: parse_bool                                                 >>
        realsize:   parse_octal12                                              >>
        take!(17) /* padding to 512 */                                         >>
        call!(parse_extra_sparses, isextended, add_to_vec(&mut sparses, sps))  >>
        (PaxHeader {
            atime:      atime,
            ctime:      ctime,
            offset:     offset,
            longnames:  longnames,
            sparses:    sparses,
            isextended: isextended,
            realsize:   realsize,
        })
    )
}

/*
 * UStar Posix parsing
 */

named!(parse_ustar00_extra_posix<&[u8], UStarExtraHeader<'_>>, do_parse!(prefix: parse_str155 >> take!(12) >> (UStarExtraHeader::PosixUStar(PosixUStarHeader { prefix: prefix }))));

fn parse_ustar00_extra(i: &[u8], flag: TypeFlag) -> IResult<&[u8], UStarExtraHeader<'_>> {
    match flag {
        TypeFlag::PaxInterexchangeFormat => do_parse!(i, header: parse_ustar00_extra_pax >> (UStarExtraHeader::Pax(header))),
        _                                => parse_ustar00_extra_posix(i)
    }
}

fn parse_ustar00(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader<'_>> {
    do_parse!(i,
        tag!("00")                                  >>
        uname:    parse_str32                       >>
        gname:    parse_str32                       >>
        devmajor: parse_octal8                      >>
        devminor: parse_octal8                      >>
        extra:    call!(parse_ustar00_extra, flag)  >>
        (ExtraHeader::UStar(UStarHeader {
            magic:    "ustar\0",
            version:  "00",
            uname:    uname,
            gname:    gname,
            devmajor: devmajor,
            devminor: devminor,
            extra:    extra
        }))
    )
}

fn parse_ustar(i: &[u8], flag: TypeFlag) -> IResult<&[u8], ExtraHeader<'_>> {
    do_parse!(i, tag!("ustar\0") >> ustar: call!(parse_ustar00, flag) >> (ustar))
}

/*
 * Posix tar archive header parsing
 */

named!(parse_posix<&[u8], ExtraHeader<'_>>, do_parse!(take!(255) >> (ExtraHeader::Padding))); /* padding to 512 */

fn parse_maybe_longname(i: &[u8], flag: TypeFlag) -> IResult<&[u8], &str> {
    match flag {
         TypeFlag::GNULongName => parse_str512(i),
         _                     => Err(nom::Err::Error(error_position!(i, ErrorKind::Complete)))
    }
}

fn parse_header(i: &[u8]) -> IResult<&[u8], PosixHeader<'_>> {
    do_parse!(i,
        name:     parse_str100                                       >>
        mode:     parse_octal8                                       >>
        uid:      parse_octal8                                       >>
        gid:      parse_octal8                                       >>
        size:     parse_octal12                                      >>
        mtime:    parse_octal12                                      >>
        chksum:   parse_str8                                         >>
        typeflag: parse_type_flag                                    >>
        linkname: parse_str100                                       >>
        ustar:    alt!(call!(parse_ustar, typeflag) | parse_posix)   >>
        longname: opt!(call!(parse_maybe_longname, typeflag))        >>
        (PosixHeader {
            name:     longname.unwrap_or(name),
            mode:     mode,
            uid:      uid,
            gid:      gid,
            size:     size,
            mtime:    mtime,
            chksum:   chksum,
            typeflag: typeflag,
            linkname: linkname,
            ustar:    ustar
        })
    )
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
    do_parse!(i, contents: take!(size as usize) >> take!(padding as usize) >> (contents))
}

/*
 * Tar entry header + contents parsing
 */

named!(parse_entry<&[u8], TarEntry<'_>>, do_parse!(
    header:   parse_header                        >>
    contents: call!(parse_contents, header.size)  >>
    (TarEntry {
        header: header,
        contents: &contents
    })
));

/*
 * Tar archive parsing
 */

fn filter_entries(entries: Vec<TarEntry<'_>>) -> Vec<TarEntry<'_>> {
    /* Filter out empty entries */
    entries.into_iter().filter(|e| e.header.name != "").collect::<Vec<TarEntry<'_>>>()
}

pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry<'_>>> {
    do_parse!(i, entries: map!(many0!(parse_entry), filter_entries) >> eof!() >> (entries))
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
