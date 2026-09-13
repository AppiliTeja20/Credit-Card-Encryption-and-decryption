package com.example.pantoken.exception;

/** Thrown when a caller references a token that does not exist (or was already revoked). */
public class TokenNotFoundException extends RuntimeException {
    public TokenNotFoundException(String token) {
        super("No vault record found for token: " + token);
    }
}
