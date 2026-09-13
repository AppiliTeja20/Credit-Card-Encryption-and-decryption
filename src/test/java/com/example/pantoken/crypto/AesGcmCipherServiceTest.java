package com.example.pantoken.crypto;

import com.example.pantoken.model.EncryptedPan;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmCipherServiceTest {

    private final KeyProvider keyProvider = new KeyProvider();
    private final AesGcmCipherService cipherService = new AesGcmCipherService();

    @Test
    void encryptThenDecryptRoundTripsToOriginalPan() {
        String pan = "4111111111111111";
        SecretKey key = keyProvider.keyForVersion(keyProvider.currentVersion());

        EncryptedPan encrypted = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_abc");
        String decrypted = cipherService.decrypt(encrypted, key, "tok_abc");

        assertEquals(pan, decrypted);
    }

    @Test
    void ciphertextNeverEqualsPlaintextOrLeaksIt() {
        String pan = "4111111111111111";
        SecretKey key = keyProvider.keyForVersion(keyProvider.currentVersion());
        EncryptedPan encrypted = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_abc");

        String ciphertextAsString = new String(encrypted.getCiphertext());
        assertNotEquals(pan, ciphertextAsString);
        assertFalse(ciphertextAsString.contains(pan));
    }

    @Test
    void twoEncryptionsOfSamePanProduceDifferentCiphertextAndIv() {
        String pan = "4111111111111111";
        SecretKey key = keyProvider.keyForVersion(keyProvider.currentVersion());

        EncryptedPan first = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_a");
        EncryptedPan second = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_b");

        assertFalse(java.util.Arrays.equals(first.getIv(), second.getIv()));
        assertFalse(java.util.Arrays.equals(first.getCiphertext(), second.getCiphertext()));
    }

    @Test
    void decryptFailsIfCiphertextIsTampered() {
        String pan = "4111111111111111";
        SecretKey key = keyProvider.keyForVersion(keyProvider.currentVersion());
        EncryptedPan encrypted = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_abc");

        byte[] tampered = encrypted.getCiphertext();
        tampered[0] ^= 0x01; // flip a bit
        EncryptedPan tamperedEncryptedPan = new EncryptedPan(tampered, encrypted.getIv(), encrypted.getKeyVersion());

        assertThrows(IllegalStateException.class,
                () -> cipherService.decrypt(tamperedEncryptedPan, key, "tok_abc"));
    }

    @Test
    void decryptFailsIfTokenAadDoesNotMatch() {
        String pan = "4111111111111111";
        SecretKey key = keyProvider.keyForVersion(keyProvider.currentVersion());
        EncryptedPan encrypted = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_original");

        assertThrows(IllegalStateException.class,
                () -> cipherService.decrypt(encrypted, key, "tok_swapped"));
    }

    @Test
    void decryptFailsWithWrongKey() {
        String pan = "4111111111111111";
        SecretKey key = keyProvider.keyForVersion(keyProvider.currentVersion());
        EncryptedPan encrypted = cipherService.encrypt(pan, key, keyProvider.currentVersion(), "tok_abc");

        int newVersion = keyProvider.rotate();
        SecretKey wrongKey = keyProvider.keyForVersion(newVersion);

        assertThrows(IllegalStateException.class,
                () -> cipherService.decrypt(encrypted, wrongKey, "tok_abc"));
    }
}
