use std::str::from_utf8;
use std::result::Result;
use nom::*;

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

/* TODO: support more vendor specific */
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

macro_rules! take_str_eat_garbage (
    ( $i:expr, $size:expr ) => (
        chain!($i,
            s: map_res!(take_until!("\0"), from_utf8)                  ~
            length: expr_opt!({($size as usize).checked_sub(s.len())}) ~
            take!(length),
            ||{
                s
            }
        )
    );
);

named!(parse_str4<&[u8], &str>, take_str_eat_garbage!(4));
named!(parse_str8<&[u8], &str>, take_str_eat_garbage!(8));
named!(parse_str32<&[u8], &str>, take_str_eat_garbage!(32));
named!(parse_str100<&[u8], &str>, take_str_eat_garbage!(100));
named!(parse_str155<&[u8], &str>, take_str_eat_garbage!(155));
named!(parse_str512<&[u8], &str>, take_str_eat_garbage!(512));

macro_rules! take_until_expr_with_limit_consume(
  ($i:expr, $submac:ident!( $($args:tt)* ), $stop: expr, $limit: expr) => (
    {
      let mut begin = 0;
      let mut remaining = $i.len();
      let mut res = Vec::new();
      let mut cnt = 0;
      let mut err = false;
      let mut append = true;
      loop {
        match $submac!(&$i[begin..], $($args)*) {
          IResult::Done(i,o) => {
            if append {
              if $stop(&o) {
                append = false;
              } else {
                res.push(o);
              }
            }
            begin += remaining - i.len();
            remaining = i.len();
            cnt = cnt + 1;
            if cnt == $limit {
              break
            }
          },
          IResult::Error(_)  => {
            err = true;
            break;
          },
          IResult::Incomplete(_) => {
            break;
          }
        }
      }
      if err {
        IResult::Error(Err::Position(ErrorKind::TakeUntil,$i))
      } else if cnt == $limit {
        IResult::Done(&$i[begin..], res)
      } else {
        IResult::Incomplete(Needed::Unknown)
      }
    }
  );
  ($i:expr, $f:expr, $stop: expr, $limit: expr) => (
    take_until_expr_with_limit_consume!($i, call!($f), $stop, $limit);
  );
);

/*
 * Octal string parsing
 */

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

fn parse_octal(i: &[u8], n: usize) -> IResult<&[u8], u64> {
    map_res!(i, take_str_eat_garbage!(n), octal_to_u64)
}

named!(parse_octal8<&[u8], u64>, apply!(parse_octal, 8));
named!(parse_octal12<&[u8], u64>, apply!(parse_octal, 12));

/*
 * TypeFlag parsing
 */

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
        'L' => TypeFlag::GNULongName,
        'A' ... 'Z' => TypeFlag::VendorSpecific,
        _ => TypeFlag::NormalFile
    }
}

fn bytes_to_type_flag(i: &[u8]) -> TypeFlag {
    char_to_type_flag(i[0] as char)
}

named!(parse_type_flag<&[u8], TypeFlag>, map!(take!(1), bytes_to_type_flag));

/*
 * Sparse parsing
 */

named!(parse_one_sparse<&[u8], Sparse>, map!(pair!(parse_octal12, parse_octal12), |(offset, numbytes)| Sparse { offset: offset, numbytes: numbytes }));

fn parse_sparses_with_limit(i: &[u8], limit: usize) -> IResult<&[u8], Vec<Sparse>> {
    take_until_expr_with_limit_consume!(i, parse_one_sparse, |s: &Sparse| s.offset == 0 && s.numbytes == 0, limit)
}

fn add_to_vec<'a, 'b>(sparses: &'a mut Vec<Sparse>, extra: &'b mut Vec<Sparse>) -> &'a mut Vec<Sparse> {
    while sparses.len() != 0 {
      extra.pop().map(|s| sparses.push(s));
    }
    sparses
}

fn parse_extra_sparses<'a, 'b>(i: &'a [u8], isextended: bool, sparses: &'b mut Vec<Sparse>) -> IResult<&'a [u8], &'b mut Vec<Sparse>> {
    if isextended {
        chain!(i,
            mut sps:       apply!(parse_sparses_with_limit, 21) ~
            extended:      parse_bool                     ~
            take!(7) /* padding to 512 */                 ~
            extra_sparses: apply!(parse_extra_sparses, extended, add_to_vec(sparses, &mut sps)),
            ||{
                extra_sparses
            }
        )
    } else {
        IResult::Done(i, sparses)
    }
}

fn parse_pax_extra_sparses<'a, 'b>(i: &'a [u8], h: &'b mut PaxHeader) -> IResult<&'a [u8], &'b mut Vec<Sparse>> {
    parse_extra_sparses(i, h.isextended, &mut h.sparses)
}

/*
 * Boolean parsing
 */

fn to_bool(i: &[u8]) -> bool {
    i[0] != 0
}

named!(parse_bool<&[u8], bool>, map!(take!(1), to_bool));

/*
 * UStar PAX extended parsing
 */

named!(parse_ustar00_extra_pax<&[u8], PaxHeader>, map!(tuple!(parse_octal12, parse_octal12, parse_octal12, parse_str4, take!(1), apply!(parse_sparses_with_limit, 4), parse_bool, parse_octal12, take!(17) /* padding to 512 */),
    |(atime, ctime, offset, longnames, _, sparses, isextended, realsize, _)|{
        PaxHeader {
            atime:         atime,
            ctime:         ctime,
            offset:        offset,
            longnames:     longnames,
            sparses:       sparses,
            isextended:    isextended,
            realsize:      realsize,
        }
    }
));

/*
 * UStar Posix parsing
 */

named!(parse_ustar00_extra_posix<&[u8], UStarExtraHeader>, map!(pair!(parse_str155, take!(12)), |(prefix, _)| UStarExtraHeader::PosixUStar(PosixUStarHeader { prefix: prefix })));

fn parse_ustar00_extra<'a, 'b>(i: &'a [u8], flag: &'b TypeFlag) -> IResult<&'a [u8], UStarExtraHeader<'a>> {
    match *flag {
        TypeFlag::PaxInterexchangeFormat => {
            chain!(i,
                mut header: parse_ustar00_extra_pax ~
                apply!(parse_pax_extra_sparses, &mut header),
                ||{
                    UStarExtraHeader::Pax(header)
                }
            )
        },
        _ => parse_ustar00_extra_posix(i)
    }
}

fn parse_ustar00<'a, 'b>(i: &'a [u8], flag: &'b TypeFlag) -> IResult<&'a [u8], ExtraHeader<'a>> {
    map!(i, tuple!(tag!("00"), parse_str32, parse_str32, parse_octal8, parse_octal8, apply!(parse_ustar00_extra, flag)),
        |(_, uname, gname, devmajor, devminor, extra)|{
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

fn parse_ustar<'a, 'b>(i: &'a [u8], flag: &'b TypeFlag) -> IResult<&'a [u8], ExtraHeader<'a>> {
    map!(i, pair!(tag!("ustar\0"), apply!(parse_ustar00, flag)), |(_, ustar)| ustar)
}

/*
 * Posix tar archive header parsing
 */

named!(parse_posix<&[u8], ExtraHeader>, map!(take!(255), |_| ExtraHeader::Padding)); /* padding to 512 */

fn parse_header<'a>(i: &'a [u8]) -> IResult<&'a [u8], PosixHeader<'a>> {
    let mut err_res = None;
    let res = chain!(i,
        name:     parse_str100    ~
        mode:     parse_str8      ~
        uid:      parse_octal8    ~
        gid:      parse_octal8    ~
        size:     parse_octal12   ~
        mtime:    parse_octal12   ~
        chksum:   parse_str8      ~
        typeflag: parse_type_flag ~
        linkname: parse_str100    ~
        ustar:    alt!(apply!(parse_ustar, &typeflag) | parse_posix),
        ||{
            let real_name = match typeflag {
                TypeFlag::GNULongName => {
                    let name_res = parse_str512(&i[512..]);
                    match name_res {
                        IResult::Done(_, long_name) => long_name,
                        IResult::Error(e) => {
                            err_res = Some(IResult::Error(e));
                            name
                        },
                        IResult::Incomplete(i) => {
                            err_res = Some(IResult::Incomplete(i));
                            name
                        }
                    }
                },
                _ => name
            };

            PosixHeader {
                name:     real_name,
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
    );

    err_res.unwrap_or(
        if let IResult::Done(i, h) = res {
            if h.typeflag == TypeFlag::GNULongName {
                IResult::Done(&i[512..], h)
            } else {
                IResult::Done(i, h)
            }
        } else {
            res
        }
    )
}

/*
 * Contents parsing
 */

fn parse_contents(i: &[u8], size: u64) -> IResult<&[u8], &[u8]> {
    let trailing = size % 512;
    let padding = match trailing {
        0 => 0,
        t => 512 - t
    };
    map!(i, pair!(take!(size as usize), take!(padding as usize)), |(contents, _)| contents)
}

/*
 * Tar entry header + contents parsing
 */

named!(parse_entry<&[u8], TarEntry>, chain!(
    header:   parse_header ~
    contents: apply!(parse_contents, header.size),
    ||{
        TarEntry {
            header: header,
            contents: contents
        }
    }
));

/*
 * Tar archive parsing
 */

fn filter_entries(entries: Vec<TarEntry>) -> Vec<TarEntry> {
    /* Filter out empty entries */
    entries.into_iter().filter(|e| e.header.name != "").collect::<Vec<TarEntry>>()
}

pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry>> {
    map!(i, pair!(map!(many0!(parse_entry), filter_entries), eof), |(entries, _)| entries)
}

/*
 * Tests
 */

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
