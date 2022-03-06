pub mod ops {

    /// Decides if the path is safe to attach events to.
    pub fn filter(path: &String) -> bool {
        let blacklist = vec![
            "/proc",
            "/sys",
            "/dev",
            "/etc",
            // "/tmp",
            "/run",
            "/var",
            "/lib",
            "/bin",
            "/sbin",
            "/usr",
            "/opt",
            "/boot",
            // "/root",
        ];
        for item in blacklist {
            if path.starts_with(item) {
                return false;
            }
        }
        true
    }
}