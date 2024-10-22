use chacha20poly1305::{aead::KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    error::{PacketError, Result},
    Role,
};

pub(crate) fn compute_salt(
    local_pub_key: &[u8],
    remote_pub_key: &[u8],
    psk: Option<&[u8]>,
) -> Result<[u8; 32]> {
    let mut keys = [0u8; 64];
    if local_pub_key <= remote_pub_key {
        keys[..32].copy_from_slice(local_pub_key);
        keys[32..].copy_from_slice(remote_pub_key);
    } else {
        keys[..32].copy_from_slice(remote_pub_key);
        keys[32..].copy_from_slice(local_pub_key);
    }
    let hash = Sha256::digest(keys);

    let salt = if let Some(psk) = psk {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(psk).map_err(|_| PacketError::KeyDerivation)?;
        mac.update(&hash);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&code_bytes);
        salt
    } else {
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&hash);
        salt
    };

    Ok(salt)
}

pub(crate) fn derive_ciphers(
    shared_secret: &[u8],
    role: Role,
    salt: &[u8],
) -> Result<(XChaCha20Poly1305, XChaCha20Poly1305)> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut key_material = [0u8; 64]; // 32 bytes for each key
    hk.expand(b"key expansion", &mut key_material)
        .map_err(|_| PacketError::KeyDerivation)?;

    let (key1_bytes, key2_bytes) = key_material.split_at(32);

    let cipher1 = XChaCha20Poly1305::new(key1_bytes.into());
    let cipher2 = XChaCha20Poly1305::new(key2_bytes.into());

    // Assign ciphers based on role
    let (cipher_enc, cipher_dec) = match role {
        Role::Client => (cipher1, cipher2),
        Role::Server => (cipher2, cipher1),
    };

    Ok((cipher_enc, cipher_dec))
}
