package com.example.pantoken.crypto;

import com.example.pantoken.model.EncryptedPan;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AES-256-GCM authenticated encryption via the BouncyCastle JCE provider.
 *
 * Design choices:
 *  - GCM gives us confidentiality AND integrity (a tampered ciphertext fails
 *    to decrypt), which a plain CBC mode would not.
 *  - A fresh random 96-bit IV is generated for every single encryption call
 *    and stored alongside the ciphertext -- IVs must never repeat for the
 *    same key, but they do not need to be secret.
 *  - The token itself is bound in as Additional Authenticated Data (AAD),
 *    so a ciphertext record can never be silently swapped onto a different
 *    token and successfully decrypt.
 */
public final class AesGcmCipherService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;   // 96-bit, the NIST-recommended size for GCM
    private static final int TAG_LENGTH_BITS = 128;  // full-length authentication tag

    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptedPan encrypt(String plaintextPan, SecretKey key, int keyVersion, String aadToken) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION, KeyProvider.PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            cipher.updateAAD(aadToken.getBytes(StandardCharsets.UTF_8));

            byte[] ciphertext = cipher.doFinal(plaintextPan.getBytes(StandardCharsets.UTF_8));
            return new EncryptedPan(ciphertext, iv, keyVersion);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PAN encryption failed", e);
        }
    }

    public String decrypt(EncryptedPan encryptedPan, SecretKey key, String aadToken) {
        byte[] plaintextBytes = null;
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, KeyProvider.PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, encryptedPan.getIv()));
            cipher.updateAAD(aadToken.getBytes(StandardCharsets.UTF_8));

            plaintextBytes = cipher.doFinal(encryptedPan.getCiphertext());
            return new String(plaintextBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PAN decryption failed (bad key, tampered data, or wrong token binding)", e);
        } finally {
            if (plaintextBytes != null) {
                Arrays.fill(plaintextBytes, (byte) 0); // best-effort scrub of plaintext from the heap
            }
        }
    }
}
