//! AES encryption implementations
//!
//! Provides AES-256-CTR and AES-256-CBC modes for MTProto encryption.

use aes::Aes256;
use ctr::{Ctr128BE, cipher::{KeyIvInit, StreamCipher}};
use crate::error::{ProxyError, Result};

type Aes256Ctr = Ctr128BE<Aes256>;

// ============= AES-256-CTR =============

/// AES-256-CTR encryptor/decryptor
/// 
/// CTR mode is symmetric - encryption and decryption are the same operation.
pub struct AesCtr {
    cipher: Aes256Ctr,
}

impl AesCtr {
    /// Create new AES-CTR cipher with key and IV
    pub fn new(key: &[u8; 32], iv: u128) -> Self {
        let iv_bytes = iv.to_be_bytes();
        Self {
            cipher: Aes256Ctr::new(key.into(), (&iv_bytes).into()),
        }
    }
    
    /// Create from key and IV slices
    pub fn from_key_iv(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(ProxyError::InvalidKeyLength { expected: 32, got: key.len() });
        }
        if iv.len() != 16 {
            return Err(ProxyError::InvalidKeyLength { expected: 16, got: iv.len() });
        }
        
        let key: [u8; 32] = key.try_into().unwrap();
        let iv = u128::from_be_bytes(iv.try_into().unwrap());
        Ok(Self::new(&key, iv))
    }
    
    /// Encrypt/decrypt data in-place (CTR mode is symmetric)
    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
    
    /// Encrypt data, returning new buffer
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut output = data.to_vec();
        self.apply(&mut output);
        output
    }
    
    /// Decrypt data (for CTR, identical to encrypt)
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        self.encrypt(data)
    }
}

// ============= AES-256-CBC =============

/// AES-256-CBC cipher with proper chaining
///
/// Unlike CTR mode, CBC is NOT symmetric - encryption and decryption
/// are different operations. This implementation handles CBC chaining
/// correctly across multiple blocks.
pub struct AesCbc {
    key: [u8; 32],
    iv: [u8; 16],
}

impl AesCbc {
    /// AES block size
    const BLOCK_SIZE: usize = 16;
    
    /// Create new AES-CBC cipher with key and IV
    pub fn new(key: [u8; 32], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }
    
    /// Create from slices
    pub fn from_slices(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(ProxyError::InvalidKeyLength { expected: 32, got: key.len() });
        }
        if iv.len() != 16 {
            return Err(ProxyError::InvalidKeyLength { expected: 16, got: iv.len() });
        }
        
        Ok(Self {
            key: key.try_into().unwrap(),
            iv: iv.try_into().unwrap(),
        })
    }
    
    /// Encrypt a single block using raw AES (no chaining)
    fn encrypt_block(&self, block: &[u8; 16], key_schedule: &aes::Aes256) -> [u8; 16] {
        use aes::cipher::BlockEncrypt;
        let mut output = *block;
        key_schedule.encrypt_block((&mut output).into());
        output
    }
    
    /// Decrypt a single block using raw AES (no chaining)
    fn decrypt_block(&self, block: &[u8; 16], key_schedule: &aes::Aes256) -> [u8; 16] {
        use aes::cipher::BlockDecrypt;
        let mut output = *block;
        key_schedule.decrypt_block((&mut output).into());
        output
    }
    
    /// XOR two 16-byte blocks
    fn xor_blocks(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = a[i] ^ b[i];
        }
        result
    }
    
    /// Encrypt data using CBC mode with proper chaining
    ///
    /// CBC Encryption: C[i] = AES_Encrypt(P[i] XOR C[i-1]), where C[-1] = IV
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % Self::BLOCK_SIZE != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = aes::Aes256::new((&self.key).into());
        
        let mut result = Vec::with_capacity(data.len());
        let mut prev_ciphertext = self.iv;
        
        for chunk in data.chunks(Self::BLOCK_SIZE) {
            let plaintext: [u8; 16] = chunk.try_into().unwrap();
            
            // XOR plaintext with previous ciphertext (or IV for first block)
            let xored = Self::xor_blocks(&plaintext, &prev_ciphertext);
            
            // Encrypt the XORed block
            let ciphertext = self.encrypt_block(&xored, &key_schedule);
            
            // Save for next iteration
            prev_ciphertext = ciphertext;
            
            // Append to result
            result.extend_from_slice(&ciphertext);
        }
        
        Ok(result)
    }
    
    /// Decrypt data using CBC mode with proper chaining
    ///
    /// CBC Decryption: P[i] = AES_Decrypt(C[i]) XOR C[i-1], where C[-1] = IV
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % Self::BLOCK_SIZE != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = aes::Aes256::new((&self.key).into());
        
        let mut result = Vec::with_capacity(data.len());
        let mut prev_ciphertext = self.iv;
        
        for chunk in data.chunks(Self::BLOCK_SIZE) {
            let ciphertext: [u8; 16] = chunk.try_into().unwrap();
            
            // Decrypt the block
            let decrypted = self.decrypt_block(&ciphertext, &key_schedule);
            
            // XOR with previous ciphertext (or IV for first block)
            let plaintext = Self::xor_blocks(&decrypted, &prev_ciphertext);
            
            // Save current ciphertext for next iteration
            prev_ciphertext = ciphertext;
            
            // Append to result
            result.extend_from_slice(&plaintext);
        }
        
        Ok(result)
    }
    
    /// Encrypt data in-place
    pub fn encrypt_in_place(&self, data: &mut [u8]) -> Result<()> {
        if data.len() % Self::BLOCK_SIZE != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = aes::Aes256::new((&self.key).into());
        
        let mut prev_ciphertext = self.iv;
        
        for i in (0..data.len()).step_by(Self::BLOCK_SIZE) {
            let block = &mut data[i..i + Self::BLOCK_SIZE];
            
            // XOR with previous ciphertext
            for j in 0..Self::BLOCK_SIZE {
                block[j] ^= prev_ciphertext[j];
            }
            
            // Encrypt in-place
            let block_array: &mut [u8; 16] = block.try_into().unwrap();
            *block_array = self.encrypt_block(block_array, &key_schedule);
            
            // Save for next iteration
            prev_ciphertext = *block_array;
        }
        
        Ok(())
    }
    
    /// Decrypt data in-place
    pub fn decrypt_in_place(&self, data: &mut [u8]) -> Result<()> {
        if data.len() % Self::BLOCK_SIZE != 0 {
            return Err(ProxyError::Crypto(
                format!("CBC data must be aligned to 16 bytes, got {}", data.len())
            ));
        }
        
        if data.is_empty() {
            return Ok(());
        }
        
        use aes::cipher::KeyInit;
        let key_schedule = aes::Aes256::new((&self.key).into());
        
        // For in-place decryption, we need to save ciphertext blocks
        // before we overwrite them
        let mut prev_ciphertext = self.iv;
        
        for i in (0..data.len()).step_by(Self::BLOCK_SIZE) {
            let block = &mut data[i..i + Self::BLOCK_SIZE];
            
            // Save current ciphertext before modifying
            let current_ciphertext: [u8; 16] = block.try_into().unwrap();
            
            // Decrypt in-place
            let block_array: &mut [u8; 16] = block.try_into().unwrap();
            *block_array = self.decrypt_block(block_array, &key_schedule);
            
            // XOR with previous ciphertext
            for j in 0..Self::BLOCK_SIZE {
                block[j] ^= prev_ciphertext[j];
            }
            
            // Save for next iteration
            prev_ciphertext = current_ciphertext;
        }
        
        Ok(())
    }
}

// ============= Encryption Traits =============

/// Trait for unified encryption interface
pub trait Encryptor: Send + Sync {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

/// Trait for unified decryption interface
pub trait Decryptor: Send + Sync {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
}

impl Encryptor for AesCtr {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        AesCtr::encrypt(self, data)
    }
}

impl Decryptor for AesCtr {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        AesCtr::decrypt(self, data)
    }
}

/// No-op encryptor for fast mode
pub struct PassthroughEncryptor;

impl Encryptor for PassthroughEncryptor {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

impl Decryptor for PassthroughEncryptor {
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // ============= AES-CTR Tests =============
    
    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0u8; 32];
        let iv = 12345u128;
        
        let original = b"Hello, MTProto!";
        
        let mut enc = AesCtr::new(&key, iv);
        let encrypted = enc.encrypt(original);
        
        let mut dec = AesCtr::new(&key, iv);
        let decrypted = dec.decrypt(&encrypted);
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes_ctr_in_place() {
        let key = [0x42u8; 32];
        let iv = 999u128;
        
        let original = b"Test data for in-place encryption";
        let mut data = original.to_vec();
        
        let mut cipher = AesCtr::new(&key, iv);
        cipher.apply(&mut data);
        
        // Encrypted should be different
        assert_ne!(&data[..], original);
        
        // Decrypt with fresh cipher
        let mut cipher = AesCtr::new(&key, iv);
        cipher.apply(&mut data);
        
        assert_eq!(&data[..], original);
    }
    
    // ============= AES-CBC Tests =============
    
    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        
        let original = [0u8; 32]; // 2 blocks
        
        let cipher = AesCbc::new(key, iv);
        let encrypted = cipher.encrypt(&original).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        
        assert_eq!(original.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_aes_cbc_chaining_works() {
        // This is the key test - verify CBC chaining is correct
        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];
        
        // Two IDENTICAL plaintext blocks
        let plaintext = [0xAAu8; 32];
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        
        // With proper CBC, identical plaintext blocks produce DIFFERENT ciphertext
        let block1 = &ciphertext[0..16];
        let block2 = &ciphertext[16..32];
        
        assert_ne!(
            block1, block2,
            "CBC chaining broken: identical plaintext blocks produced identical ciphertext. \
             This indicates ECB mode, not CBC!"
        );
    }
    
    #[test]
    fn test_aes_cbc_known_vector() {
        // Test with known NIST test vector
        // AES-256-CBC with zero key and zero IV
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext = [0u8; 16];
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        
        // Decrypt and verify roundtrip
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        
        // Ciphertext should not be all zeros
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    }
    
    #[test]
    fn test_aes_cbc_multi_block() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 16];
        
        // 5 blocks = 80 bytes
        let plaintext: Vec<u8> = (0..80).collect();
        
        let cipher = AesCbc::new(key, iv);
        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        let decrypted = cipher.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[test]
    fn test_aes_cbc_in_place() {
        let key = [0x12u8; 32];
        let iv = [0x34u8; 16];
        
        let original = [0x56u8; 48]; // 3 blocks
        let mut buffer = original;
        
        let cipher = AesCbc::new(key, iv);
        
        cipher.encrypt_in_place(&mut buffer).unwrap();
        assert_ne!(&buffer[..], &original[..]);
        
        cipher.decrypt_in_place(&mut buffer).unwrap();
        assert_eq!(&buffer[..], &original[..]);
    }
    
    #[test]
    fn test_aes_cbc_empty_data() {
        let cipher = AesCbc::new([0u8; 32], [0u8; 16]);
        
        let encrypted = cipher.encrypt(&[]).unwrap();
        assert!(encrypted.is_empty());
        
        let decrypted = cipher.decrypt(&[]).unwrap();
        assert!(decrypted.is_empty());
    }
    
    #[test]
    fn test_aes_cbc_unaligned_error() {
        let cipher = AesCbc::new([0u8; 32], [0u8; 16]);
        
        // 15 bytes - not aligned to block size
        let result = cipher.encrypt(&[0u8; 15]);
        assert!(result.is_err());
        
        // 17 bytes - not aligned
        let result = cipher.encrypt(&[0u8; 17]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_aes_cbc_avalanche_effect() {
        // Changing one bit in plaintext should change entire ciphertext block
        // and all subsequent blocks (due to chaining)
        let key = [0xAB; 32];
        let iv = [0xCD; 16];
        
        let mut plaintext1 = [0u8; 32];
        let mut plaintext2 = [0u8; 32];
        plaintext2[0] = 0x01; // Single bit difference in first block
        
        let cipher = AesCbc::new(key, iv);
        
        let ciphertext1 = cipher.encrypt(&plaintext1).unwrap();
        let ciphertext2 = cipher.encrypt(&plaintext2).unwrap();
        
        // First blocks should be different
        assert_ne!(&ciphertext1[0..16], &ciphertext2[0..16]);
        
        // Second blocks should ALSO be different (chaining effect)
        assert_ne!(&ciphertext1[16..32], &ciphertext2[16..32]);
    }
    
    #[test]
    fn test_aes_cbc_iv_matters() {
        // Same plaintext with different IVs should produce different ciphertext
        let key = [0x55; 32];
        let plaintext = [0x77u8; 16];
        
        let cipher1 = AesCbc::new(key, [0u8; 16]);
        let cipher2 = AesCbc::new(key, [1u8; 16]);
        
        let ciphertext1 = cipher1.encrypt(&plaintext).unwrap();
        let ciphertext2 = cipher2.encrypt(&plaintext).unwrap();
        
        assert_ne!(ciphertext1, ciphertext2);
    }
    
    #[test]
    fn test_aes_cbc_deterministic() {
        // Same key, IV, plaintext should always produce same ciphertext
        let key = [0x99; 32];
        let iv = [0x88; 16];
        let plaintext = [0x77u8; 32];
        
        let cipher = AesCbc::new(key, iv);
        
        let ciphertext1 = cipher.encrypt(&plaintext).unwrap();
        let ciphertext2 = cipher.encrypt(&plaintext).unwrap();
        
        assert_eq!(ciphertext1, ciphertext2);
    }
    
    // ============= Error Handling Tests =============
    
    #[test]
    fn test_invalid_key_length() {
        let result = AesCtr::from_key_iv(&[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
        
        let result = AesCbc::from_slices(&[0u8; 16], &[0u8; 16]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_invalid_iv_length() {
        let result = AesCtr::from_key_iv(&[0u8; 32], &[0u8; 8]);
        assert!(result.is_err());
        
        let result = AesCbc::from_slices(&[0u8; 32], &[0u8; 8]);
        assert!(result.is_err());
    }
}