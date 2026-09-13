package com.example.pantoken.model;

import java.util.Base64;

/**
 * Everything needed to decrypt a PAN later, and nothing more.
 * This is the ONLY form in which a PAN is ever stored by this service.
 */
public final class EncryptedPan {

    private final byte[] ciphertext; // includes the GCM auth tag
    private final byte[] iv;
    private final int keyVersion;

    public EncryptedPan(byte[] ciphertext, byte[] iv, int keyVersion) {
        this.ciphertext = ciphertext.clone();
        this.iv = iv.clone();
        this.keyVersion = keyVersion;
    }

    public byte[] getCiphertext() {
        return ciphertext.clone();
    }

    public byte[] getIv() {
        return iv.clone();
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    /** Safe to log/print: no plaintext is derivable from this. */
    @Override
    public String toString() {
        return "EncryptedPan{ciphertext=" + Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext)
                + ", keyVersion=" + keyVersion + "}";
    }
}
