use std::str::from_utf8;
use nom::IResult;

#[derive(Debug,PartialEq,Eq)]
pub struct PosixHeader<'a> {
    pub name:     & 'a str,
    pub mode:     & 'a str,
    pub uid:      & 'a str,
    pub gid:      & 'a str,
    pub size:     & 'a str,
    pub mtime:    & 'a str,
    pub chksum:   & 'a str,
    pub typeflag: char,
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
        linkname: map_res!(take!(100), from_utf8),
        /* TODO: ustar */
        ||{
            PosixHeader {
                name:     name,
                mode:     mode,
                uid:      uid,
                gid:      gid,
                size:     size,
                mtime:    mtime,
                chksum:   chksum,
                typeflag: typeflag[0] as char,
                linkname: linkname,
                ustar:    None
            }
        }
    )
}

fn parse_entry(i: &[u8]) -> IResult<&[u8], TarEntry> {
    chain!(i,
        header: parse_header,
        /* TODO: contents */
        ||{
            TarEntry {
                header: header,
                contents: ""
            }
        }
    )
}

pub fn parse_tar(i: &[u8]) -> IResult<&[u8], Vec<TarEntry>> {
    many0!(i, parse_entry)
}
