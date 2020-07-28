use std::env;
use std::path::PathBuf;
use std::slice;
use std::mem;
use std::convert::TryInto;

use read_process_memory::{TryIntoProcessHandle, CopyAddress, ProcessHandle};
use procfs::process::{Process, MemoryMap, MMapPath};
use libc::pid_t;

fn main() {
    let mut args = env::args();
    let _name = args.next().unwrap();
    let pid: pid_t = args.next().unwrap().parse().unwrap();
    let value_ptr_str = args.next().unwrap();
    let value_ptr: u64 = if value_ptr_str.starts_with("0x") {
        u64::from_str_radix(&value_ptr_str[2..], 16).unwrap()
    } else {
        value_ptr_str.parse().unwrap()
    };

    let proc_info = ProcInfo::new(pid);

    let handle = pid.try_into_process_handle().unwrap();
    let mut buf = [0u8; 4];
    handle.copy_address(value_ptr as usize, &mut buf).unwrap();
    println!("value at {:x}: {}", value_ptr, u32::from_le_bytes(buf));

    let mut pointer_paths = vec![vec![(value_ptr, 0)]];
    for level in 1.. {
        println!("level {}", level);
        pointer_paths = search_next_level(&proc_info, pointer_paths);
        for path in &pointer_paths {
            println!("{:x?}", path);
        }
        let possible_paths = pointer_paths.iter().filter(|path| proc_info.is_in_binary(path[0].0));
        for path in possible_paths {
            println!("FOUND POSSIBLE PATH:");
            println!("{:x?}", path);
        }
    }
}

fn search_next_level(proc_info: &ProcInfo, pointer_paths: Vec<Vec<(u64, u64)>>) -> Vec<Vec<(u64, u64)>> {
    let mut res = Vec::new();

    for path in pointer_paths {
        let (offset, addrs) = match proc_info.find_offset_of(path[0].0, 0x400) {
            Some(data) => data,
            None => {
                println!("throwing away {:#x}", path[0].0);
                continue;
            }
        };
        let new_paths = addrs.into_iter()
            .map(|addr| {
                let mut new_path = Vec::with_capacity(path.len() + 1);
                new_path.push((addr, offset));
                new_path.extend(&path);
                new_path
            });
        res.extend(new_paths);
    }

    res
}

struct ProcInfo {
    handle: ProcessHandle,
    proc: Process,
    maps: Vec<(MemoryMap, Vec<usize>)>,
    proc_exe: PathBuf,
}

impl ProcInfo {
    pub fn new(pid: pid_t) -> ProcInfo {
        let handle = pid.try_into_process_handle().unwrap();
        let process = Process::new(pid).unwrap();
        let maps = process.maps().unwrap();
        let maps = maps.into_iter()
            .filter_map(|map| {
                let usize_size = mem::size_of::<usize>() as u64;
                let (start, end) = map.address;
                assert_eq!(start % usize_size as u64, 0);
                assert_eq!(end % usize_size as u64, 0);
                println!("{:#x}", start);
                println!("{:?}", map);
                let len = (end - start) / usize_size as u64;
                let mut memory = vec![0usize; len as usize];
                let byte_slice = unsafe { slice::from_raw_parts_mut(memory.as_mut_ptr() as *mut u8, (end - start) as usize) };
                match handle.copy_address(start as usize, byte_slice) {
                    Ok(()) => Some((map, memory)),
                    Err(_) => None
                }
            }).collect();
        ProcInfo {
            handle,
            maps,
            proc_exe: process.exe().unwrap(),
            proc: process,
        }
    }

    pub fn is_in_binary(&self, addr: u64) -> bool {
        for (map, _) in &self.maps {
            match &map.pathname {
                MMapPath::Path(path) if path == &self.proc_exe => {
                    if map.address.0 <= addr && addr <= map.address.1 {
                        return true;
                    }
                }
                _ => ()
            }
        }
        false
    }

    pub fn read_usize_at(&self, addr: u64) -> usize {
        let mut buf = [0u8; mem::size_of::<usize>()];
        self.handle.copy_address(addr as usize, &mut buf).unwrap();
        usize::from_ne_bytes(buf)
    }

    pub fn map_of(&self, addr: u64) -> &(MemoryMap, Vec<usize>) {
        self.maps.iter()
            .filter(|(m, _)| m.address.0 <= addr && addr <= m.address.1)
            .next().unwrap()
    }

    pub fn find_offset_of(&self, addr: u64, max_offset: u64) -> Option<(u64, Vec<u64>)> {
        let usize_size = mem::size_of::<usize>() as u64;
        let (map, _) = self.map_of(addr);
        let mut offset = 0;

        while offset <= max_offset && addr - offset >= map.address.0 {
            let ptr = addr - offset;

            println!("testing offset {:x}, addr {:x}", offset, ptr);
            let vec = self.search_for_addr(ptr);
            if vec.len() > 0 {
                return Some((offset, vec));
            }
            offset += usize_size;
        }
        None
    }

    pub fn search_for_addr(&self, addr: u64) -> Vec<u64> {
        let mut res = Vec::new();
        let usize_size = mem::size_of::<usize>() as u64;

        for (map, memory) in &self.maps {
            for (i, val) in memory.iter().copied().enumerate() {
                if addr == val as u64 {
                    res.push(map.address.0 + i as u64 * usize_size);
                }
            }
        }
        res
    }
}

// fn print_relevant_paths() {
//     for map in maps {
//         match &map.pathname {
//             MMapPath::Path(path) if *path == process_exe => {
//                 println!("address: {:x?}, perms: {}, offset: {}, dev: {:?}, inode: {}, pathname: {:?}", map.address, map.perms, map.offset, map.dev, map.inode, map.pathname);
//             }
//             _ => ()
//         }
//     }
// }