package com.example.pantoken.exception;

/**
 * Thrown when a caller requests the raw PAN back (detokenize) without the
 * elevated authorization required for that operation. Only the masked
 * view of a PAN is available by default.
 */
public class UnauthorizedDetokenizationException extends RuntimeException {
    public UnauthorizedDetokenizationException() {
        super("Caller is not authorized to retrieve the raw PAN for this token");
    }
}
