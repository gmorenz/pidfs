#![allow(unused_imports)]

use std::{ffi::{OsStr, OsString}, collections::HashMap, time::{SystemTime, Duration}, os::unix::prelude::OsStrExt, error::Error};

use fuser::{Filesystem, FileAttr, FileType, consts::FOPEN_DIRECT_IO};
use libc::{ENOSYS, ENOENT, EEXIST};

#[derive(Debug)]
struct PidFs {
    /// Inode -> Pid -> FileData
    file_data: Vec<HashMap<u32, Vec<u8>>>,
    file_names: HashMap<OsString, u32>,
}

fn default_file_attributes(inode: u64, uid: u32, gid: u32, perm: u16) -> FileAttr {
    fuser::FileAttr {
        ino: inode,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: perm,
        nlink: 1,
        uid: uid,
        gid: gid,
        rdev: 0,
        blksize: 1,
        flags: 0,
    }
}

impl Filesystem for PidFs {
    fn lookup(&mut self, req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEntry) {
        if parent != 1 {
            eprintln!("We don't support subdirs");
            return reply.error(ENOENT);
        }

        let mut name_split = name.as_bytes().split(|b| b == &b'_');
        let filename = match name_split.next() {
            Some(name) => name,
            None => {
                eprintln!("Invalid filename {name:?}");
                return reply.error(ENOENT);
            }
        };

        let pid_parse_result = name_split.next().map(|pid_bytes| {
            use std::str::FromStr;
            let pid_str = std::str::from_utf8(pid_bytes)?;
            u32::from_str(pid_str).map_err(|e| Box::new(e) as Box<dyn Error>)
        }).transpose();

        if name_split.next().is_some() {
            eprintln!("Invalid filename (too many _) {name:?}");
            return reply.error(ENOENT);
        }

        let pid: Option<u32> = match pid_parse_result {
            Ok(pid) => pid,
            Err(e) => {
                eprintln!("Failed to parse pid: {e:?}");
                return reply.error(ENOENT);
            }
        };

        if let Some(&inode_lower) = self.file_names.get(OsStr::from_bytes(filename)) {
            let (perm, inode) =
                if let Some(pid) = pid {
                    (0o444, ((pid as u64) << 32) | (inode_lower as u64)) // read only
                } else {
                    (0o666, inode_lower as u64) // write only
                };

            reply.entry(
                &Duration::new(0, 0),
                &default_file_attributes(inode, req.uid(), req.gid(), perm),
                0, // TODO: What is generation?
            )
        } else {
            reply.error(ENOENT);
        }
    }

    fn create(
        &mut self,
        req: &fuser::Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        if parent != 1 {
            eprintln!("We don't support subdirs");
            return reply.error(ENOENT);
        }

        if name.as_bytes().contains(&b'_') {
            eprintln!("Can't create files with _ in name");
            return reply.error(ENOSYS);
        }

        if self.file_names.contains_key(name) {
            eprintln!("File already exists");
            return reply.error(EEXIST);
        }

        let inode = self.file_data.len() as u64;

        if inode >= 2u64.pow(32) {
            eprintln!("Out of inodes");
            return reply.error(ENOSYS);
        }

        self.file_data.push(HashMap::new());
        self.file_names.insert(name.to_owned(), inode as u32);

        eprintln!("Created file");
        reply.created(
            &Duration::new(0, 0),
            &default_file_attributes(inode, req.uid(), req.gid(), 0o666),
            0,
            inode, // File Handle... probably fine to re-use inode
            0,
        )
    }

    fn write(
        &mut self,
        req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        assert_eq!(ino, fh);
        assert!(ino < self.file_data.len() as _);
        assert!(ino != 0);
        if ino == 1 {
            return reply.error(ENOSYS);
        }

        let file_data = self.file_data[ino as usize].entry(req.pid()).or_default();
        file_data.extend_from_slice(data);

        reply.written(data.len() as _);
    }

    fn getattr(&mut self, req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        eprintln!("Getattr {ino}");
        if ino == 1 {
            // Root file
            let gid = req.gid();
            let uid = req.uid();
            return reply.attr(
                &Duration::new(0, 0),
                &fuser::FileAttr {
                    ino,
                    size: 0,
                    blocks: 0,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                    crtime: SystemTime::UNIX_EPOCH,
                    kind: FileType::Directory,
                    perm: 0o777,
                    nlink: 1,
                    uid,
                    gid,
                    rdev: 0,
                    blksize: 1,
                    flags: 0,
                }
            )
        }

        if ino < 2u64.pow(32) {
            // We don't acknowledge the existence of the write files
            eprintln!("Trying to get attr on dir");
            return reply.error(ENOENT);
        }

        return reply.attr(
            &Duration::new(0, 0),
            &default_file_attributes(ino, req.uid(), req.gid(), 0o444)
        )
    }

    fn readdir(&mut self, _req: &fuser::Request<'_>, ino: u64, fh: u64, offset: i64, mut reply: fuser::ReplyDirectory) {
        if dbg!(ino != 1) || dbg!(fh != 1) || dbg!(offset < 0) || dbg!(offset as u64 > usize::MAX as u64) {
            eprintln!("ino: {ino}");
            eprintln!("Invalid readdir call");
            return reply.error(ENOSYS);
        }

        let entries =
            self.file_names.iter()
            .flat_map(|(filename, &inode_lower)|
                self.file_data[inode_lower as usize].keys().map(move |&pid| {
                    let mut name = filename.clone();
                    name.push("_");
                    name.push(&format!("{pid}"));

                    let inode = ((pid as u64) << 32) | (inode_lower as u64);

                    (inode, FileType::RegularFile, name)
                })
            )
            .chain(std::iter::once((1, FileType::Directory, ".".into())))
            .enumerate();

        for (index, (inode, filetype, name)) in entries.skip(offset as usize) {
            eprintln!("\tDir entry: {inode} {index} {name:?}");
            let full = reply.add(inode, 1 + index as i64, filetype, &name);
            if full {
                break
            }
        }

        reply.ok();
    }

    fn opendir(&mut self, _req: &fuser::Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        if ino != 1 {
            return reply.error(ENOSYS);
        }
        reply.opened(1, 0);
    }

    fn releasedir(&mut self, _req: &fuser::Request<'_>, ino: u64, _fh: u64, _flags: i32, reply: fuser::ReplyEmpty) {
        if ino != 1 {
            return reply.error(ENOSYS);
        }
        reply.ok()
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        inode: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData
    ) {
        eprintln!("Read inode: {inode} offset: {offset} size: {size}");

        if offset < 0 || offset as u64 > usize::MAX as u64 {
            eprintln!("Invalid offset");
            return reply.error(ENOSYS)
        }
        let offset = offset as usize;

        if inode < 2u64.pow(32) {
            eprintln!("Invalid inode");
            return reply.error(ENOENT)
        }

        let lower_inode = inode as u32; // Defined to truncate in the reference
        let pid = (inode >> 32) as u32;

        if let Some(file_datum) = self.file_data.get(lower_inode as usize) {
            if let Some(bytes) = file_datum.get(&pid) {
                let max_size = bytes.len() - offset;
                let read_size = (size as usize).min(max_size);
                eprintln!("Returning {read_size} bytes");
                return reply.data(&bytes[offset.. offset+read_size]);
            }
        }

        // Fall through is an error, we failed to find either the file or pid data
        eprintln!("File not found");
        return reply.error(ENOENT)
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        reply.opened(ino, FOPEN_DIRECT_IO)
    }

    fn release(&mut self, _req: &fuser::Request<'_>, _ino: u64, _fh: u64, _flags: i32, _lock_owner: Option<u64>, _flush: bool, reply: fuser::ReplyEmpty) {
        reply.ok()
    }
}

fn main() {
    env_logger::init();

    let fs = PidFs {
        file_data: vec![
            HashMap::new(), // Empty inode 0
            HashMap::new(), // Empty data for root inode
        ],
        file_names: HashMap::new(),
    };
    fuser::mount2(fs, "pidfs", &[]).unwrap();
}
