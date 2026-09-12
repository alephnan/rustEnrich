use std::io::{self, Write};

/// Stops serializers before they allocate beyond a configured response budget.
pub(crate) struct LimitedWriter {
    pub bytes: Vec<u8>,
    limit: usize,
}

impl LimitedWriter {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("serialization limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct CountingWriter(pub usize);
impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialization limit exceeded"))?;
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
