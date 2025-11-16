#![allow(unused)]

/// NBD constants for the newstyle handshake (as per QEMU implementation)
pub(crate) const NBDMAGIC: u64 = 0x4E42444D41474943; // "NBDMAGIC"
pub(crate) const IHAVEOPT: u64 = 0x49484156454F5054; // "IHAVEOPT"

// --- Server Flags (u16) ---
pub(crate) const NBD_FLAG_FIXED_NEWSTYLE: u16 = 0x0001; // Server MUST set this
pub(crate) const NBD_FLAG_NO_ZEROES: u16 = 0x0004; // Server supports NBD_OPTS_FLAG_NO_ZEROES

// --- Client Flags (u32) ---
pub(crate) const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = 0x0001; // Client MUST set this
pub(crate) const NBD_FLAG_C_NO_ZEROES: u32 = 0x0004; // Client supports NBD_OPTS_FLAG_NO_ZEROES

// --- Transmission Flags (u16) --- these need to be public for export spec
pub const NBD_FLAG_HAS_FLAGS: u16 = 0x0001; // Server can send flags
pub const NBD_FLAG_READ_ONLY: u16 = 0x0002; // Export is read-only
pub const NBD_FLAG_SEND_FLUSH: u16 = 0x0004; // Server supports NBD_CMD_FLUSH
pub const NBD_FLAG_SEND_FUA: u16 = 0x0008; // Server supports NBD_CMD_FLAG_FUA
pub const NBD_FLAG_SEND_TRIM: u16 = 0x0020; // Server supports NBD_CMD_TRIM

// --- Option Types (u32) ---
pub(crate) const NBD_OPT_EXPORT_NAME: u32 = 1;
pub(crate) const NBD_OPT_ABORT: u32 = 2;
pub(crate) const NBD_OPT_LIST: u32 = 3;
pub(crate) const NBD_OPT_STARTTLS: u32 = 5;
pub(crate) const NBD_OPT_INFO: u32 = 6;
pub(crate) const NBD_OPT_GO: u32 = 7;
pub(crate) const NBD_REP_MAGIC: u64 = 0x3e889045565a9;

// --- Option Replies (u32) ---
pub(crate) const NBD_REP_ACK: u32 = 1;
pub(crate) const NBD_REP_SERVER: u32 = 2; // A reply to NBD_OPT_LIST
pub(crate) const NBD_REP_INFO: u32 = 3;
pub(crate) const NBD_REP_FLAG_ERROR: u32 = 1 << 31;
pub(crate) const NBD_REP_ERR_UNSUP: u32 = 1 | NBD_REP_FLAG_ERROR;
pub(crate) const NBD_REP_ERR_POLICY: u32 = 2 | NBD_REP_FLAG_ERROR;
pub(crate) const NBD_REP_ERR_INVALID: u32 = 3 | NBD_REP_FLAG_ERROR;
pub(crate) const NBD_REP_ERR_PLATFORM: u32 = 4 | NBD_REP_FLAG_ERROR;
pub(crate) const NBD_REP_ERR_TLS_REQD: u32 = 5 | NBD_REP_FLAG_ERROR;
pub(crate) const NBD_REP_ERR_UNKNOWN: u32 = 6 | NBD_REP_FLAG_ERROR;
pub(crate) const NBD_REP_ERR_BLOCK_SIZE_REQD: u32 = 8 | NBD_REP_FLAG_ERROR;
// --- NBD Command Types (u16) ---
pub(crate) const NBD_CMD_READ: u16 = 0;
pub(crate) const NBD_CMD_WRITE: u16 = 1;
pub(crate) const NBD_CMD_DISC: u16 = 2;
pub(crate) const NBD_CMD_FLUSH: u16 = 3;
pub(crate) const NBD_CMD_TRIM: u16 = 4;

// --- NBD Command Magics ---
pub(crate) const NBD_REQUEST_MAGIC: u32 = 0x25609513;
pub(crate) const NBD_REPLY_MAGIC: u32 = 0x67446698;

// info types
pub(crate) const NBD_INFO_EXPORT: u16 = 0;
pub(crate) const NBD_INFO_NAME: u16 = 1;
pub(crate) const NBD_INFO_DESCRIPTION: u16 = 2;
pub(crate) const NBD_INFO_BLOCK_SIZE: u16 = 3;
