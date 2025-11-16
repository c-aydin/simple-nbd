use std::future::Future;
use std::io;

use bytes::Bytes;
use bytes::BytesMut;
use tracing::{debug, warn};

use super::export::{NbdReply, NbdRequest, ReplyType, RequestType};

/// Trait defining the interface for NBD backends.
pub trait NbdBackend {
    fn size(&self) -> u64;
    fn handle_request(&mut self, req: &NbdRequest) -> impl Future<Output = NbdReply> + Send;
}

/// A simple, fixed-size, in-memory block device.
/// Not really async, but good for testing
pub struct MemoryBackend {
    data: BytesMut,
}

impl NbdBackend for MemoryBackend {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn handle_request(&mut self, req: &NbdRequest) -> impl Future<Output = NbdReply> + Send {
        tracing::trace!(
            handle = req.handle,
            "Handling request in MemoryBackend: {:?}",
            req.request_type
        );
        let reply = match req.request_type {
            RequestType::Read => self.read(req),
            RequestType::Write => self.write(req),
            RequestType::Flush => self.flush(req),
            RequestType::Trim => self.trim(req),
            _ => {
                warn!("Unsupported request type: {:?}", req.request_type);
                NbdReply {
                    handle: req.handle,
                    request_type: req.request_type,
                    reply_type: ReplyType::Error,
                    error_code: io::ErrorKind::Unsupported as u32,
                    data: None,
                }
            }
        };
        async move { reply }
    }
}

impl MemoryBackend {
    pub fn new(size: usize) -> Self {
        MemoryBackend {
            data: BytesMut::zeroed(size),
        }
    }

    /// Read a block of data from the storage.
    pub fn read(&self, req: &NbdRequest) -> NbdReply {
        let offset = req.offset as usize;
        let length = req.length as usize;
        debug!(offset, length, "Reading from storage");

        let mut reply = NbdReply {
            handle: req.handle,
            request_type: req.request_type,
            reply_type: ReplyType::Data,
            error_code: 0,
            data: None,
        };
        let end = offset.saturating_add(length);
        if end > self.data.len() {
            warn!(offset, length, max = self.size(), "Read out of bounds");
            reply.reply_type = ReplyType::Error;
            reply.error_code = io::ErrorKind::InvalidInput as u32;
        } else {
            reply.data = Some(Bytes::copy_from_slice(&self.data[offset..end]));
        }
        tracing::trace!(handle = reply.handle, "Read reply prepared");
        reply
    }

    /// Write a block of data to the storage.
    pub fn write(&mut self, req: &NbdRequest) -> NbdReply {
        let offset = req.offset as usize;
        let length = req.length as usize;
        let mut reply = NbdReply {
            handle: req.handle,
            request_type: req.request_type,
            reply_type: ReplyType::Ack,
            error_code: 0,
            data: None,
        };
        debug!(offset, length, "Writing to storage");
        let end = offset.saturating_add(length);
        if end > self.data.len() {
            warn!(offset, length, max = self.size(), "Write out of bounds");
            reply.reply_type = ReplyType::Error;
            reply.error_code = io::ErrorKind::InvalidInput as u32;
        } else {
            match &req.data {
                Some(data) => {
                    self.data[offset..end].copy_from_slice(data);
                }
                None => {
                    warn!("Write request missing data");
                    reply.reply_type = ReplyType::Error;
                    reply.error_code = io::ErrorKind::InvalidInput as u32;
                }
            }
        }
        reply
    }

    /// Flush (a no-op for in-memory).
    pub fn flush(&mut self, req: &NbdRequest) -> NbdReply {
        debug!("Flushing storage (no-op)");
        NbdReply {
            handle: req.handle,
            request_type: req.request_type,
            reply_type: ReplyType::Ack,
            error_code: 0,
            data: None,
        }
    }

    pub fn trim(&mut self, req: &NbdRequest) -> NbdReply {
        debug!("Trimming storage (no-op)");
        NbdReply {
            handle: req.handle,
            request_type: req.request_type,
            reply_type: ReplyType::Ack,
            error_code: 0,
            data: None,
        }
    }
}
