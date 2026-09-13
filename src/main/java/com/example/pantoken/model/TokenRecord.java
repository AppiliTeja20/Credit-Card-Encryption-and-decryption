package com.example.pantoken.model;

import java.time.Instant;

/**
 * What actually lives in the vault store, keyed by token.
 * Notice there is no field here that can hold a raw PAN -- that is
 * enforced structurally, not just by convention.
 */
public final class TokenRecord {

    private final String token;
    private final EncryptedPan encryptedPan;
    private final String first6; // BIN/IIN -- not sensitive under PCI DSS, safe to store in clear
    private final String last4;
    private final String brand;
    private final int panLength;
    private final Instant createdAt;

    public TokenRecord(String token, EncryptedPan encryptedPan, String first6, String last4, String brand, int panLength, Instant createdAt) {
        this.token = token;
        this.encryptedPan = encryptedPan;
        this.first6 = first6;
        this.last4 = last4;
        this.brand = brand;
        this.panLength = panLength;
        this.createdAt = createdAt;
    }

    public String getFirst6() {
        return first6;
    }

    public int getPanLength() {
        return panLength;
    }

    public String getToken() {
        return token;
    }

    public EncryptedPan getEncryptedPan() {
        return encryptedPan;
    }

    public String getLast4() {
        return last4;
    }

    public String getBrand() {
        return brand;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
