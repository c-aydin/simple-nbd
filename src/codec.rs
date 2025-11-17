use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, error, info, trace, warn};

use crate::constants::*;

/// Codec internal states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    /// Server: Waiting for the 4-byte client flags.
    ExpectClientFlags,
    /// Client: Waiting for the 16-byte server greeting.
    ExpectServerGreeting,
    /// Both: In the option haggling loop.
    Haggling,
    /// Both: Handshake is done, now in transmission phase.
    Transmission,
    /// Aborted
    Aborted,
}

impl SessionState {
    fn as_u8(&self) -> u8 {
        *self as u8
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => SessionState::ExpectClientFlags,
            1 => SessionState::ExpectServerGreeting,
            2 => SessionState::Haggling,
            3 => SessionState::Transmission,
            4 => SessionState::Aborted,
            _ => SessionState::Aborted,
        }
    }
}

impl From<u8> for SessionState {
    fn from(value: u8) -> Self {
        SessionState::from_u8(value)
    }
}

type ShareableState = Arc<AtomicU8>;

/// Represents a single, logical NBD message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NbdMessage {
    // --- Handshake ---
    ServerGreeting {
        flags: u16,
    },
    ClientFlags {
        flags: u32,
    },

    // --- Option Haggling ---
    OptionClanger {
        option_id: u32,
        data: Bytes,
    },
    SimpleReply {
        option_id: u32,
        reply_type: u32,
        data: Bytes,
    },

    // --- Transition to Transmission ---
    ExportInfo {
        option_id: u32,
        request_type: u16,
        size: u64,
        flags: u16,
    },

    LegacyExportInfo {
        size: u64,
        flags: u16,
    },

    // --- Transmission Phase ---
    CmdRead {
        cookie: u64,
        offset: u64,
        length: u32,
    },
    CmdWrite {
        cookie: u64,
        offset: u64,
        data: Bytes,
    },
    CmdDisc {
        cookie: u64,
    },
    CmdFlush {
        cookie: u64,
    },
    CmdTrim {
        cookie: u64,
        offset: u64,
        length: u32,
    },
    CmdReply {
        error: u32,
        cookie: u64,
        data: Option<Bytes>,
    },
}

pub struct NbdCodec {
    state: ShareableState,
    /// We must store the length of pending READ requests
    /// to know how much data to expect in a CmdReply.
    /// Key: cookie, Value: length
    pending_reads: HashMap<u64, u32>,
    /// Whether to add zeroes where appropriate if client does not support NO_ZEROES
    add_zeroes: bool,
}

impl NbdCodec {
    /// Create a new codec for a server (expects client flags).
    pub fn new_server() -> Self {
        info!("Creating new NBD codec (Server-side)");
        Self {
            state: Arc::new(AtomicU8::new(SessionState::ExpectClientFlags.as_u8())),
            pending_reads: HashMap::new(),
            add_zeroes: false,
        }
    }

    /// Create a new codec for a client (expects server greeting).
    pub fn new_client() -> Self {
        info!("Creating new NBD codec (Client-side)");
        Self {
            state: Arc::new(AtomicU8::new(SessionState::ExpectServerGreeting.as_u8())),
            pending_reads: HashMap::new(),
            add_zeroes: false,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state.load(Ordering::SeqCst).into()
    }

    pub fn shareable_state(&self) -> ShareableState {
        self.state.clone()
    }

    pub fn set_state(&self, new_state: SessionState) {
        self.state.store(new_state.as_u8(), Ordering::SeqCst);
    }

    pub fn set_shared_state(&mut self, new_state: ShareableState) {
        self.state = new_state;
    }

    /// Helper to transition to the Transmission phase.
    fn transition_to_transmission(&mut self) {
        info!("Transitioning to Transmission phase. Handshake complete.");
        self.set_state(SessionState::Transmission);
    }

    fn transition_to_aborted(&mut self) {
        info!("Transitioning to Aborted state. Handshake aborted.");
        self.set_state(SessionState::Aborted);
    }
}

// =========================================================================
// === ENCODER Implementation (Stateless)
// =========================================================================

impl Encoder<NbdMessage> for NbdCodec {
    type Error = io::Error;

    /// Encodes a logical `NbdMessage` into bytes in the `dst` buffer.
    fn encode(&mut self, item: NbdMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        trace!(state = ?self.state, "Encoding Message");
        match item {
            // --- Handshake ---
            NbdMessage::ServerGreeting { flags } => {
                dst.reserve(18);
                dst.put_u64(NBDMAGIC); // 8 bytes
                dst.put_u64(IHAVEOPT); // 8 bytes
                dst.put_u16(flags); // 2 bytes
            }
            NbdMessage::ClientFlags { flags } => {
                dst.reserve(4);
                dst.put_u32(flags); // 4 bytes
            }

            // --- Option Haggling ---
            NbdMessage::OptionClanger { option_id, data } => {
                let data_len = data.len() as u32;
                dst.reserve(16 + data.len());
                dst.put_u64(IHAVEOPT); // 8 bytes
                dst.put_u32(option_id); // 4 bytes
                dst.put_u32(data_len); // 4 bytes
                dst.put_slice(&data); // Variable data
            }
            NbdMessage::SimpleReply {
                option_id,
                reply_type,
                data,
            } => {
                dst.reserve(16 + data.len());
                dst.put_u64(NBD_REP_MAGIC); // 8 bytes
                dst.put_u32(option_id); // 4 bytes
                dst.put_u32(reply_type); // 4 bytes
                dst.put_u32(data.len() as u32); // 4 bytes
                dst.put_slice(&data); // Variable data
            }

            // --- Transition ---
            NbdMessage::ExportInfo {
                option_id,
                request_type,
                size,
                flags,
            } => {
                dst.reserve(48);
                dst.put_u64(NBD_REP_MAGIC); // 8 bytes
                dst.put_u32(option_id); // 4 bytes
                dst.put_u32(NBD_REP_INFO); // 4 bytes
                dst.put_u32(12); // 4 bytes
                dst.put_u16(request_type); // 2 bytes
                dst.put_u64(size); // 8 bytes
                dst.put_u16(flags); // 2 bytes
            }

            NbdMessage::LegacyExportInfo { size, flags } => {
                dst.put_u64(size); // 8 bytes
                dst.put_u16(flags); // 2 bytes
                dst.put_bytes(0, 124);

                self.transition_to_transmission();
            }

            // --- Transmission: Requests ---
            NbdMessage::CmdRead {
                cookie,
                offset,
                length,
            } => {
                dst.reserve(28);
                dst.put_u32(NBD_REQUEST_MAGIC); // 4
                dst.put_u16(0); // flags (2)
                dst.put_u16(NBD_CMD_READ); // type (2)
                dst.put_u64(cookie); // 8
                dst.put_u64(offset); // 8
                dst.put_u32(length); // 4
                // A client must remember this!
                debug!(?cookie, length, "Encoder: Storing pending read");
                self.pending_reads.insert(cookie, length);
            }
            NbdMessage::CmdWrite {
                cookie,
                offset,
                data,
            } => {
                let length = data.len() as u32;
                dst.reserve(28 + length as usize);
                dst.put_u32(NBD_REQUEST_MAGIC); // 4
                dst.put_u16(0); // flags (2)
                dst.put_u16(NBD_CMD_WRITE); // type (2)
                dst.put_u64(cookie); // 8
                dst.put_u64(offset); // 8
                dst.put_u32(length); // 4
                dst.put_slice(&data);
            }
            NbdMessage::CmdDisc { cookie } => {
                dst.reserve(28);
                dst.put_u32(NBD_REQUEST_MAGIC); // 4
                dst.put_u16(0); // flags (2)
                dst.put_u16(NBD_CMD_DISC); // type (2)
                dst.put_u64(cookie); // 8
                dst.put_u64(0); // offset (8)
                dst.put_u32(0); // length (4)
            }
            NbdMessage::CmdFlush { cookie } => {
                dst.reserve(28);
                dst.put_u32(NBD_REQUEST_MAGIC);
                dst.put_u16(0);
                dst.put_u16(NBD_CMD_FLUSH);
                dst.put_u64(cookie);
                dst.put_u64(0);
                dst.put_u32(0);
            }
            NbdMessage::CmdTrim {
                cookie,
                offset,
                length,
            } => {
                dst.reserve(28);
                dst.put_u32(NBD_REQUEST_MAGIC);
                dst.put_u16(0);
                dst.put_u16(NBD_CMD_TRIM);
                dst.put_u64(cookie);
                dst.put_u64(offset);
                dst.put_u32(length);
            }

            // --- Transmission: Replies ---
            NbdMessage::CmdReply {
                error,
                cookie,
                data,
            } => {
                dst.reserve(16);
                dst.put_u32(NBD_REPLY_MAGIC); // 4
                dst.put_u32(error); // 4
                dst.put_u64(cookie); // 8
                if let Some(data) = data {
                    // This is a READ reply. Data is sent immediately after.
                    dst.put_slice(&data);
                }
                // For non-read replies, we're done.
            }
        }
        Ok(())
    }
}

// =========================================================================
// === DECODER Implementation (Stateful)
// =========================================================================

impl Decoder for NbdCodec {
    type Item = NbdMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        trace!(state = ?self.state, "Decode loop start. src len = {}", src.len());

        //tracing::trace!("Full server message({} bytes): {:?}", src.len(), src);

        match self.state() {
            // --- Handshake States ---
            SessionState::ExpectServerGreeting => {
                if src.len() < 18 {
                    trace!("ExpectServerGreeting: Need 18 bytes, got {}", src.len());
                    return Ok(None);
                }
                let greeting = src.split_to(18);
                let magic = (&greeting[0..8]).get_u64();
                let ihaveopt = (&greeting[8..16]).get_u64();
                if magic != NBDMAGIC || ihaveopt != IHAVEOPT {
                    error!("Invalid NBD greeting received: {:?}", &greeting[..]);
                    return Err(Error::new(ErrorKind::InvalidData, "Invalid NBD greeting"));
                }
                let flags = (&greeting[16..]).get_u16();
                info!(?flags, "Received valid server greeting");
                self.set_state(SessionState::Haggling);
                Ok(Some(NbdMessage::ServerGreeting { flags }))
            }
            SessionState::ExpectClientFlags => {
                if src.len() < 4 {
                    trace!("ExpectClientFlags: Need 4 bytes, got {}", src.len());
                    return Ok(None);
                }
                let flags = src.split_to(4).get_u32();
                info!(?flags, "Received client flags");
                self.set_state(SessionState::Haggling);
                if flags & NBD_FLAG_C_FIXED_NEWSTYLE == 0 {
                    warn!(?flags, "Client does not support fixed newstyle. Closing.");
                }
                if flags & NBD_FLAG_C_NO_ZEROES == 0 {
                    warn!(
                        ?flags,
                        "Client did not set NO_ZEROES flag. Will try to add zeroes where appropriate."
                    );
                    self.add_zeroes = true;
                }
                Ok(Some(NbdMessage::ClientFlags { flags }))
            }

            // --- Main Haggling Loop ---
            SessionState::Haggling => {
                // We need at least 4 bytes to identify a Simple Reply,
                // which is the smallest possible identifier.
                if src.len() < 4 {
                    trace!(
                        "Haggling: Need at least 4 bytes to identify message type, got {}",
                        src.len()
                    );
                    return Ok(None);
                }

                // First, peek at the 4-byte magic for a Simple Reply.
                if src[0..4] == NBD_REP_MAGIC.to_be_bytes() {
                    // --- 1. It's a Simple Reply ---
                    // We must have the full 16-byte header to read the data length.
                    if src.len() < 16 {
                        trace!(
                            "Haggling/Reply: Need 16 header bytes to peek length, got {}",
                            src.len()
                        );
                        return Ok(None);
                    }

                    // Peek the data length *without* consuming the header.
                    // The data length is at offset 12 (4b magic + 4b option + 4b type).
                    // We use `get_u32` on a slice, which doesn't modify `src`.
                    let data_length = (&src[12..16]).get_u32() as usize;
                    let total_needed = 16 + data_length;

                    trace!(
                        ?data_length,
                        total_needed, "Haggling/Reply: Peeked Simple Reply length"
                    );

                    // Check if we have the full message (header + data).
                    if src.len() < total_needed {
                        trace!(
                            "Haggling/Reply: Need {} total bytes, got {}",
                            total_needed,
                            src.len()
                        );
                        return Ok(None);
                    }

                    // We have the full message, *now* we consume it.
                    let mut header = src.split_to(16);
                    header.advance(4); // Skip NBD_REP_MAGIC
                    let option_id = header.get_u32();
                    let reply_type = header.get_u32();
                    let data_length_from_header = header.get_u32() as usize;

                    // This assert ensures our peek logic was correct.
                    debug_assert_eq!(
                        data_length, data_length_from_header,
                        "Peeked length must match consumed length"
                    );

                    let data = src.split_to(data_length).freeze();
                    debug!(
                        ?option_id,
                        ?reply_type,
                        data_length,
                        "Haggling: Parsed Simple Reply"
                    );
                    return Ok(Some(NbdMessage::SimpleReply {
                        option_id,
                        reply_type,
                        data,
                    }));
                }

                // If it wasn't a Simple Reply, we must have at least 8 bytes
                // to identify either an Option Clanger or Export Info.
                if src.len() < 8 {
                    trace!(
                        "Haggling: Need at least 8 bytes for Option/Export, got {}",
                        src.len()
                    );
                    return Ok(None);
                }

                // Now we can peek at the first 8 bytes and *match*.
                match &src[0..8] {
                    magic if magic == IHAVEOPT.to_be_bytes() => {
                        // --- 2. It's an Option Clanger ---
                        // We must have the full 16-byte header to read the data length.
                        if src.len() < 16 {
                            trace!(
                                "Haggling/Clanger: Need 16 header bytes to peek length, got {}",
                                src.len()
                            );
                            return Ok(None);
                        }

                        // Peek the data length *without* consuming the header.
                        // The data length is at offset 12 (8b magic + 4b option).
                        let data_len = (&src[12..16]).get_u32() as usize;
                        let total_needed = 16 + data_len;

                        trace!(
                            ?data_len,
                            total_needed, "Haggling/Clanger: Peeked Option Clanger length"
                        );

                        // Check for data payload
                        if src.len() < total_needed {
                            trace!(
                                "Haggling/Clanger: Need {} total bytes, got {}",
                                total_needed,
                                src.len()
                            );
                            return Ok(None);
                        }

                        // We have the full message, *now* we consume it.
                        let mut header = src.split_to(16);
                        header.advance(8); // Skip IHAVEOPT
                        let option_id = header.get_u32();
                        let data_len_from_header = header.get_u32() as usize;

                        // This assert ensures our peek logic was correct.
                        debug_assert_eq!(
                            data_len, data_len_from_header,
                            "Peeked length must match consumed length"
                        );

                        let data = src.split_to(data_len).freeze();
                        debug!(?option_id, data_len, "Haggling: Parsed Option Clanger");

                        // Does this option trigger a state change?
                        match option_id {
                            NBD_OPT_ABORT => {
                                info!("Haggling: Client requested abort");
                                self.transition_to_aborted();
                            }
                            NBD_OPT_GO => {
                                debug!(
                                    "Haggling: Client sent NBD_OPT_GO, transitioning to transmission state"
                                );
                                self.transition_to_transmission();
                            }
                            _ => {
                                // we don't address other options here
                            }
                        }
                        Ok(Some(NbdMessage::OptionClanger { option_id, data }))
                    }
                    _ => {
                        // LLM thinks this makes sense for some reason...
                        // --- 3. It's Export Info ---
                        // (The magic number didn't match IHAVEOPT or NBD_REP_MAGIC)
                        // We already know src.len() >= 8.
                        // if src.len() < 134 {
                        //     trace!("Haggling/ExportInfo: Need 134 bytes, got {}", src.len());
                        //     return Ok(None);
                        // }

                        // // Consume export info (this message has a fixed size, so no peeking needed)
                        // let size = src.split_to(8).get_u64();
                        // let flags = src.split_to(2).get_u16();
                        // src.advance(124); // Discard 124 reserved bytes

                        // debug!(?size, ?flags, "Haggling: Parsed Export Info");
                        // self.transition_to_transmission();
                        // Ok(Some(NbdMessage::ExportInfo { size, flags }))
                        error!("Invalid magic number in haggling phase: {:?}", &src[0..8]);
                        Err(Error::new(
                            ErrorKind::InvalidData,
                            "Invalid magic in haggling phase",
                        ))
                    }
                }
            }

            // --- Transmission Phase ---
            SessionState::Transmission => {
                if src.len() < 4 {
                    trace!("Transmission: Need 4 magic bytes, got {}", src.len());
                    return Ok(None);
                }

                // In transmission, we can receive either a Request or a Reply.
                // We check the magic number.
                let magic = (&src[0..4]).get_u32();

                if magic == NBD_REQUEST_MAGIC {
                    debug!("Transmission: Identified Request Magic");
                    // --- It's a Request (Server-side) ---
                    if src.len() < 28 {
                        trace!(
                            "Transmission/Request: Need 28 header bytes, got {}",
                            src.len()
                        );
                        return Ok(None); // Not enough for header
                    }
                    let mut header = BytesMut::from(&src[0..28]);
                    let _magic = header.get_u32();
                    let flags = header.get_u16();
                    let cmd_type = header.get_u16();
                    let cookie = header.get_u64();
                    let offset = header.get_u64();
                    let length = header.get_u32();
                    debug!(
                        ?flags,
                        ?cmd_type,
                        ?cookie,
                        ?offset,
                        ?length,
                        "Transmission: Parsed Request Header"
                    );

                    if src.len() < length as usize + 28 && cmd_type == NBD_CMD_WRITE {
                        trace!(
                            "Transmission/WriteRequest: Need {} payload bytes, got {}",
                            length,
                            src.len() - 28
                        );
                        return Ok(None); // Need write payload
                    }
                    // consume the header
                    src.advance(28);

                    match cmd_type {
                        NBD_CMD_READ => {
                            // Server must remember this read to send reply
                            debug!(?cookie, ?length, "Transmission: Storing pending read");
                            self.pending_reads.insert(cookie, length);
                            Ok(Some(NbdMessage::CmdRead {
                                cookie,
                                offset,
                                length,
                            }))
                        }
                        NBD_CMD_WRITE => {
                            if src.len() < length as usize {
                                trace!(
                                    "Transmission/Write: Need {} payload bytes, got {}",
                                    length,
                                    src.len()
                                );
                                return Ok(None); // Need write payload
                            }
                            let data = src.split_to(length as usize).freeze();
                            debug!(
                                ?cookie,
                                "Transmission: Parsed Write payload ({} bytes)",
                                data.len()
                            );
                            Ok(Some(NbdMessage::CmdWrite {
                                cookie,
                                offset,
                                data,
                            }))
                        }
                        NBD_CMD_DISC => Ok(Some(NbdMessage::CmdDisc { cookie })),
                        NBD_CMD_FLUSH => Ok(Some(NbdMessage::CmdFlush { cookie })),
                        NBD_CMD_TRIM => Ok(Some(NbdMessage::CmdTrim {
                            cookie,
                            offset,
                            length,
                        })),
                        _ => {
                            error!(?cmd_type, "Received unknown NBD command type");
                            Err(Error::new(ErrorKind::InvalidData, "Unknown NBD command"))
                        }
                    }
                } else if magic == NBD_REPLY_MAGIC {
                    debug!("Transmission: Identified Reply Magic");
                    // --- It's a Reply (Client-side) ---
                    if src.len() < 16 {
                        trace!(
                            "Transmission/Reply: Need 16 header bytes, got {}",
                            src.len()
                        );
                        return Ok(None); // Not enough for header
                    }
                    let mut header = src.split_to(16);
                    header.advance(4); // Skip magic
                    let error = header.get_u32();
                    let cookie = header.get_u64();
                    debug!(?error, ?cookie, "Transmission: Parsed Reply Header");

                    // Was this a READ reply?
                    if let Some(length) = self.pending_reads.remove(&cookie) {
                        debug!(?cookie, ?length, "Transmission: Identified READ reply");
                        // Yes. We must wait for the data payload.
                        if src.len() < length as usize {
                            trace!(
                                "Transmission/ReadReply: Need {} payload bytes, got {}",
                                length,
                                src.len()
                            );
                            // Put length back in case we don't have enough data
                            self.pending_reads.insert(cookie, length);
                            return Ok(None); // Need read payload
                        }
                        let data = if error == 0 {
                            debug!(
                                ?cookie,
                                "Transmission: Parsed READ reply payload ({} bytes)", length
                            );
                            Some(src.split_to(length as usize).freeze())
                        } else {
                            error!(
                                ?cookie,
                                ?error,
                                "Transmission: READ reply has error, no data payload"
                            );
                            None // Error, no data payload
                        };
                        Ok(Some(NbdMessage::CmdReply {
                            error,
                            cookie,
                            data,
                        }))
                    } else {
                        debug!(?cookie, "Transmission: Identified non-READ reply");
                        if error != 0 {
                            warn!(?cookie, ?error, "Transmission: Non-READ reply has error");
                        }
                        // No. This was a reply for WRITE, FLUSH, etc. No data follows.
                        Ok(Some(NbdMessage::CmdReply {
                            error,
                            cookie,
                            data: None,
                        }))
                    }
                } else {
                    error!(?magic, "Invalid magic number in transmission phase");
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "Invalid magic in transmission phase",
                    ))
                }
            }
            // --- Aborted State ---
            SessionState::Aborted => {
                // just consume what's in the pipe until closed
                let len = src.len();
                src.advance(len);
                warn!("In Aborted state, discarding {} bytes", len);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_greeting_encode_decode() {
        let mut codec = NbdCodec::new_client();
        let mut buffer = BytesMut::new();

        // Server encodes
        let greeting = NbdMessage::ServerGreeting { flags: 0x0001 };
        codec
            .encode(greeting.clone(), &mut buffer)
            .expect("Encoding failed");

        assert_eq!(buffer.len(), 18);
        assert_eq!(&buffer[0..8], NBDMAGIC.to_be_bytes());
        assert_eq!(&buffer[8..16], IHAVEOPT.to_be_bytes());
        assert_eq!(&buffer[16..18], &[0x00, 0x01]);

        // Client decodes
        let decoded = codec.decode(&mut buffer).expect("Decoding failed");
        assert_eq!(decoded, Some(greeting));
        assert_eq!(codec.state(), SessionState::Haggling); // State transitioned
        assert_eq!(buffer.len(), 0); // Buffer is empty
    }

    #[test]
    fn test_option_clanger_encode_decode() {
        let mut codec = NbdCodec::new_server();
        codec.set_state(SessionState::Haggling); // Manually set for test
        let mut buffer = BytesMut::new();

        // Client encodes
        let option_data = Bytes::from_static(b"disk1");
        let clanger = NbdMessage::OptionClanger {
            option_id: NBD_OPT_EXPORT_NAME,
            data: option_data.clone(),
        };
        codec
            .encode(clanger.clone(), &mut buffer)
            .expect("Encoding failed");

        assert_eq!(buffer.len(), 16 + 5); // 16 header + 5 data
        assert_eq!(&buffer[0..8], IHAVEOPT.to_be_bytes());
        assert_eq!(&buffer[8..12], NBD_OPT_EXPORT_NAME.to_be_bytes()); // option
        assert_eq!(&buffer[12..16], (5_u32).to_be_bytes()); // length
        assert_eq!(&buffer[16..21], b"disk1");

        // Server decodes
        let decoded = codec.decode(&mut buffer).expect("Decoding failed");
        assert_eq!(decoded, Some(clanger));
        assert_eq!(codec.state(), SessionState::Haggling); // State remains
        assert_eq!(buffer.len(), 0);
    }

    #[ignore = "haven't needed to implement this yet"]
    #[test]
    fn test_export_info_transition() {
        let mut codec = NbdCodec::new_client();
        codec.set_state(SessionState::Haggling); // Client is haggling
        let mut buffer = BytesMut::new();

        // Server encodes ExportInfo (transition message)
        let export_info = NbdMessage::ExportInfo {
            option_id: 0,
            request_type: 1,
            size: 0x12345678_9ABCDEF0,
            flags: 0xABCD,
        };
        codec
            .encode(export_info.clone(), &mut buffer)
            .expect("Encoding failed");

        assert_eq!(buffer.len(), 32);

        // Client decodes
        let decoded = codec.decode(&mut buffer).expect("Decoding failed");
        assert_eq!(decoded, Some(export_info));
        assert_eq!(codec.state(), SessionState::Transmission); // STATE TRANSITIONED!
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn test_client_read_request_and_reply() {
        // --- Client perspective ---
        let mut client_codec = NbdCodec::new_client();
        client_codec.set_state(SessionState::Transmission);
        let mut client_buf = BytesMut::new();

        // Client encodes a READ request
        let read_req = NbdMessage::CmdRead {
            cookie: 0x11223344,
            offset: 1024,
            length: 512,
        };
        client_codec
            .encode(read_req.clone(), &mut client_buf)
            .unwrap();

        // Check that client is now expecting a reply for this cookie
        assert_eq!(client_codec.pending_reads.get(&0x11223344), Some(&512));

        // --- Server perspective ---
        let mut server_codec = NbdCodec::new_server();
        server_codec.set_state(SessionState::Transmission);

        // Server decodes the client's buffer
        let decoded_req = server_codec.decode(&mut client_buf).unwrap().unwrap();
        assert_eq!(decoded_req, read_req);
        assert_eq!(server_codec.pending_reads.get(&0x11223344), Some(&512));

        // --- Server encodes a reply ---
        let reply_data = Bytes::from(vec![0xAA; 512]);
        let reply_msg = NbdMessage::CmdReply {
            error: 0,
            cookie: 0x11223344,
            data: Some(reply_data.clone()),
        };
        let mut server_buf = BytesMut::new();
        server_codec
            .encode(reply_msg.clone(), &mut server_buf)
            .unwrap();

        assert_eq!(server_buf.len(), 16 + 512); // 16 header + 512 data

        // --- Client decodes the reply ---
        let decoded_reply = client_codec.decode(&mut server_buf).unwrap().unwrap();
        assert_eq!(decoded_reply, reply_msg);
        // Client should have cleared the pending read
        assert!(!client_codec.pending_reads.contains_key(&0x11223344));
    }

    #[test]
    fn test_client_write_request_and_reply() {
        // --- Client perspective ---
        let mut client_codec = NbdCodec::new_client();
        client_codec.set_state(SessionState::Transmission);
        let mut client_buf = BytesMut::new();

        // Client encodes a WRITE request
        let write_data = Bytes::from(vec![0xBB; 256]);
        let write_req = NbdMessage::CmdWrite {
            cookie: 0x44556677,
            offset: 2048,
            data: write_data.clone(),
        };
        client_codec
            .encode(write_req.clone(), &mut client_buf)
            .unwrap();

        // Client should NOT be expecting a data reply for a write
        assert!(!client_codec.pending_reads.contains_key(&0x44556677));
        assert_eq!(client_buf.len(), 28 + 256); // 28 header + 256 data

        // --- Server perspective ---
        let mut server_codec = NbdCodec::new_server();
        server_codec.set_state(SessionState::Transmission);

        // Server decodes the client's buffer
        let decoded_req = server_codec.decode(&mut client_buf).unwrap().unwrap();
        assert_eq!(decoded_req, write_req);

        // --- Server encodes a simple "OK" reply (no data) ---
        let reply_msg = NbdMessage::CmdReply {
            error: 0,
            cookie: 0x44556677,
            data: None,
        };
        let mut server_buf = BytesMut::new();
        server_codec
            .encode(reply_msg.clone(), &mut server_buf)
            .unwrap();

        assert_eq!(server_buf.len(), 16); // 16 header, no data

        // --- Client decodes the reply ---
        let decoded_reply = client_codec.decode(&mut server_buf).unwrap().unwrap();
        assert_eq!(decoded_reply, reply_msg);
    }
}
