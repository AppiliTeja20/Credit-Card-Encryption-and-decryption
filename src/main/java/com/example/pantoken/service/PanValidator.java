package com.example.pantoken.service;

import com.example.pantoken.exception.InvalidPanException;

/**
 * Validates raw PAN input before it is ever handed to the crypto layer.
 * This class never logs or stores the PAN it validates.
 */
public final class PanValidator {

    private PanValidator() {
    }

    /**
     * Strips whitespace/dashes, checks length and Luhn checksum.
     *
     * @param rawPan the PAN as supplied by the caller
     * @return the normalized (digits-only) PAN
     * @throws InvalidPanException if the PAN is malformed or fails the Luhn check
     */
    public static String normalizeAndValidate(String rawPan) {
        if (rawPan == null) {
            throw new InvalidPanException("PAN must not be null");
        }
        String digitsOnly = rawPan.replaceAll("[\\s-]", "");
        if (!digitsOnly.matches("\\d{12,19}")) {
            throw new InvalidPanException("PAN must be 12-19 digits");
        }
        if (!passesLuhnCheck(digitsOnly)) {
            throw new InvalidPanException("PAN failed Luhn checksum validation");
        }
        return digitsOnly;
    }

    /**
     * Standard Luhn (mod 10) checksum used by all major card networks.
     */
    public static boolean passesLuhnCheck(String digitsOnly) {
        int sum = 0;
        boolean doubleDigit = false;
        for (int i = digitsOnly.length() - 1; i >= 0; i--) {
            int digit = digitsOnly.charAt(i) - '0';
            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    /**
     * Rough network/brand detection from the leading digits (IIN ranges).
     * Purely cosmetic for the demo -- never used for security decisions.
     */
    public static String detectBrand(String digitsOnly) {
        if (digitsOnly.startsWith("4")) {
            return "VISA";
        }
        if (digitsOnly.matches("^5[1-5].*") || digitsOnly.matches("^2(2[2-9]|[3-6]\\d|7[01])\\d*")) {
            return "MASTERCARD";
        }
        if (digitsOnly.matches("^3[47].*")) {
            return "AMEX";
        }
        if (digitsOnly.matches("^6(011|5).*")) {
            return "DISCOVER";
        }
        return "UNKNOWN";
    }
}
