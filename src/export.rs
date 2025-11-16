use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    Read,
    Write,
    Flush,
    Trim,
    Cache,
    WriteZeroes,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyType {
    Ack,
    Data,
    Error,
}

#[derive(Clone, Debug)]
pub struct NbdRequest {
    pub cookie: u64,
    pub request_type: RequestType,
    pub offset: u64,
    pub length: u32,
    pub data: Option<Bytes>,
}

#[derive(Clone, Debug)]
pub struct NbdReply {
    pub cookie: u64,
    pub request_type: RequestType,
    pub reply_type: ReplyType,
    pub error_code: u32,
    pub data: Option<Bytes>,
}

impl NbdRequest {
    pub fn new_read(cookie: u64, offset: u64, length: u32) -> Self {
        NbdRequest {
            cookie,
            request_type: RequestType::Read,
            offset,
            length,
            data: None,
        }
    }

    pub fn new_write(cookie: u64, offset: u64, length: u32, data: Bytes) -> Self {
        NbdRequest {
            cookie,
            request_type: RequestType::Write,
            offset,
            length,
            data: Some(data),
        }
    }

    pub fn new_flush(cookie: u64) -> Self {
        NbdRequest {
            cookie,
            request_type: RequestType::Flush,
            offset: 0,
            length: 0,
            data: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NbdExportSpec {
    pub name: String,
    pub description: String,
    pub size: u64,
    pub block_size: u32,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct MpscExport {
    pub spec: NbdExportSpec,
    pub request_sender: mpsc::Sender<NbdRequest>,
    pub request_receiver: Arc<Mutex<mpsc::Receiver<NbdRequest>>>,
    pub reply_sender: mpsc::Sender<NbdReply>,
    pub reply_receiver: Arc<Mutex<mpsc::Receiver<NbdReply>>>,
}

impl MpscExport {
    pub fn new(spec: NbdExportSpec, channel_size: usize) -> Self {
        let (request_sender, request_receiver) = mpsc::channel::<NbdRequest>(channel_size);
        let (reply_sender, reply_receiver) = mpsc::channel::<NbdReply>(channel_size);

        MpscExport {
            spec,
            request_sender,
            request_receiver: Arc::new(Mutex::new(request_receiver)),
            reply_sender,
            reply_receiver: Arc::new(Mutex::new(reply_receiver)),
        }
    }
}

/// Trait for NBD Export Registry
/// Implemented without the async warning...
pub trait NbdExportRegistryExt {
    fn new_locked() -> Self;

    fn add_export(&self, export: MpscExport) -> impl Future<Output = ()> + Send;

    fn get_export(&self, name: &str) -> impl Future<Output = Option<MpscExport>> + Send;

    fn list_exports(&self) -> impl Future<Output = HashMap<String, NbdExportSpec>> + Send;
}

pub type NbdExportRegistry = Arc<Mutex<HashMap<String, MpscExport>>>;

impl NbdExportRegistryExt for NbdExportRegistry {
    fn new_locked() -> Self {
        Arc::new(Mutex::new(std::collections::HashMap::new()))
    }

    async fn add_export(&self, export: MpscExport) {
        let mut registry = self.lock().await;
        registry.insert(export.spec.name.clone(), export);
    }

    async fn get_export(&self, name: &str) -> Option<MpscExport> {
        let registry = self.lock().await;
        registry.get(name).cloned()
    }

    async fn list_exports(&self) -> HashMap<String, NbdExportSpec> {
        let registry = self.lock().await;
        registry
            .iter()
            .map(|(name, export)| (name.clone(), export.spec.clone()))
            .collect()
    }
}
