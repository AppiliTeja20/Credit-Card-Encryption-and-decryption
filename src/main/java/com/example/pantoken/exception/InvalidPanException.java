package com.example.pantoken.exception;

/** Thrown when input fails PAN format or Luhn validation before it ever reaches the crypto layer. */
public class InvalidPanException extends RuntimeException {
    public InvalidPanException(String message) {
        super(message);
    }
}
