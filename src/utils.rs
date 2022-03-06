pub mod structures {
    use std::time::{Duration, Instant};
    pub const COOLDOWN_TIME: Duration = Duration::new(5, 0); 

    pub struct Entry {
        path: String,
        timestamp: Instant
    }

    impl Entry {
        pub fn new(path: String) -> Self {
            Entry {
                path,
                timestamp: Instant::now()
            }
        }

        pub fn dead(&self) -> bool {
            self.timestamp.elapsed() > COOLDOWN_TIME
        }
    }

}