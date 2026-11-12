//! Cipher names are retained for strict source-config decoding only.
mod aead_util {
    pub const TAG_LEN: usize = 16;
}
#[path = "../shadowsocks/shadowsocks_cipher.rs"]
mod cipher;
pub use cipher::ShadowsocksCipher;
