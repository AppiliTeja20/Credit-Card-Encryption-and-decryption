package com.example.pantoken.crypto;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates opaque, non-guessable vault tokens.
 *
 * Per the task resources, tokens are Base64URL-encoded (RFC 4648 section 5)
 * so they are safe to place directly in JSON, URLs, and headers without
 * further escaping ('+', '/', and padding '=' are all avoided).
 *
 * Tokens are random and carry NO derivable relationship to the underlying
 * PAN -- unlike format-preserving encryption output, a token is not
 * "decryptable" by itself; it is only a lookup key into the vault.
 */
public final class TokenGenerator {

    private static final int TOKEN_ENTROPY_BYTES = 24; // 192 bits of entropy
    private static final String PREFIX = "tok_";

    private final SecureRandom secureRandom = new SecureRandom();

    public String generate() {
        byte[] randomBytes = new byte[TOKEN_ENTROPY_BYTES];
        secureRandom.nextBytes(randomBytes);
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        return PREFIX + encoded;
    }
}
