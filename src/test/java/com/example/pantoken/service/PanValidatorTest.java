package com.example.pantoken.service;

import com.example.pantoken.exception.InvalidPanException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PanValidatorTest {

    @Test
    void acceptsValidVisaTestPan() {
        String normalized = PanValidator.normalizeAndValidate("4111 1111 1111 1111");
        assertEquals("4111111111111111", normalized);
        assertEquals("VISA", PanValidator.detectBrand(normalized));
    }

    @Test
    void acceptsValidMastercardTestPan() {
        String normalized = PanValidator.normalizeAndValidate("5500-0000-0000-0004");
        assertEquals("MASTERCARD", PanValidator.detectBrand(normalized));
    }

    @Test
    void rejectsFailedLuhnChecksum() {
        assertThrows(InvalidPanException.class,
                () -> PanValidator.normalizeAndValidate("4111111111111112"));
    }

    @Test
    void rejectsTooShort() {
        assertThrows(InvalidPanException.class,
                () -> PanValidator.normalizeAndValidate("411111"));
    }

    @Test
    void rejectsNonDigits() {
        assertThrows(InvalidPanException.class,
                () -> PanValidator.normalizeAndValidate("4111-1111-ABCD-1111"));
    }

    @Test
    void rejectsNull() {
        assertThrows(InvalidPanException.class, () -> PanValidator.normalizeAndValidate(null));
    }
}
