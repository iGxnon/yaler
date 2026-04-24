use serde::{Deserialize, Serialize};

/// Binary frame types used inside WebSocket Binary messages.
/// Every Binary frame is prefixed with one of these bytes so a single
/// WebSocket connection can carry multiple sequential tunnel sessions.
pub const FRAME_DATA: u8 = 0x00;
pub const FRAME_EOF: u8 = 0x01;

/// First WebSocket frame (text) sent by the client to the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectReq {
    pub pw: String,
    pub host: String,
    pub port: u16,
}

/// Server reply to ConnectReq.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

impl ConnectResp {
    pub fn ok() -> Self {
        Self {
            ok: true,
            err: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            err: Some(msg.into()),
        }
    }
}

/// Resolved proxy target.
#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
}
