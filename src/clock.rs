use chrono::{DateTime, Utc};
#[cfg(test)]
use std::sync::Mutex;

/// UTC is persisted; monotonic Tokio instants are used for deadlines.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[cfg(test)]
pub(crate) struct TestClock(pub Mutex<DateTime<Utc>>);

#[cfg(test)]
impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}
