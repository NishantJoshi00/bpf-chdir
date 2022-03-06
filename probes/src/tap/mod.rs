pub const PATHLEN: usize = 256;
pub const MAPSIZE: u32 = 2048;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Path {
    pub path: [u8; PATHLEN],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct FdPid {
    pub fd: u64,
    pub pid: u64,
}

impl Default for Path {
    fn default() -> Self {
        Self { path: [0; PATHLEN] }
    }
}
