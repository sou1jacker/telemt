//! Stream wrappers for MTProto protocol layers

pub mod state;
pub mod buffer_pool;
pub mod traits;
pub mod crypto_stream;
pub mod tls_stream;
pub mod frame_stream;

// Re-export state machine types
pub use state::{
    StreamState, Transition, PollResult,
    ReadBuffer, WriteBuffer, HeaderBuffer, YieldBuffer,
};

// Re-export buffer pool
pub use buffer_pool::{BufferPool, PooledBuffer, PoolStats};

// Re-export stream implementations
pub use crypto_stream::{CryptoReader, CryptoWriter, PassthroughStream};
pub use tls_stream::{FakeTlsReader, FakeTlsWriter};
pub use frame_stream::*;