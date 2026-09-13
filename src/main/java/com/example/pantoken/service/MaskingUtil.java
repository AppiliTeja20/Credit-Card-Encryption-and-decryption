package com.example.pantoken.service;

/**
 * Single source of truth for how a PAN is allowed to be displayed.
 * Every log line and every non-privileged API response must go through here.
 *
 * Default mask keeps only the last 4 digits, matching PCI DSS 3.4 guidance
 * ("first six / last four" is also supported for receipts, via
 * {@link #maskShowFirst6Last4}).
 */
public final class MaskingUtil {

    private static final char MASK_CHAR = '*';

    private MaskingUtil() {
    }

    /** e.g. 4111111111111111 -> ************1111 */
    public static String maskShowLast4(String digitsOnlyPan) {
        return mask(digitsOnlyPan, 0, 4);
    }

    /** e.g. 4111111111111111 -> 411111******1111 (common on printed receipts) */
    public static String maskShowFirst6Last4(String digitsOnlyPan) {
        return mask(digitsOnlyPan, 6, 4);
    }

    private static String mask(String digitsOnlyPan, int showFirst, int showLast) {
        if (digitsOnlyPan == null) {
            return null;
        }
        int len = digitsOnlyPan.length();
        if (len <= showFirst + showLast) {
            // Too short to safely partially mask -- mask everything.
            return String.valueOf(MASK_CHAR).repeat(len);
        }
        StringBuilder sb = new StringBuilder(len);
        sb.append(digitsOnlyPan, 0, showFirst);
        sb.append(String.valueOf(MASK_CHAR).repeat(len - showFirst - showLast));
        sb.append(digitsOnlyPan, len - showLast, len);
        return sb.toString();
    }

    public static String last4(String digitsOnlyPan) {
        if (digitsOnlyPan == null || digitsOnlyPan.length() < 4) {
            throw new IllegalArgumentException("PAN too short to extract last 4 digits");
        }
        return digitsOnlyPan.substring(digitsOnlyPan.length() - 4);
    }

    /** BIN/IIN prefix. Not sensitive under PCI DSS -- safe to store and display in clear. */
    public static String first6(String digitsOnlyPan) {
        if (digitsOnlyPan == null || digitsOnlyPan.length() < 6) {
            throw new IllegalArgumentException("PAN too short to extract first 6 digits");
        }
        return digitsOnlyPan.substring(0, 6);
    }

    /** Renders a mask directly from pre-extracted first6/last4 fields, with no PAN in scope at all. */
    public static String composeMask(String first6, String last4, int totalLength, boolean showFirst6) {
        int middleLen = totalLength - last4.length() - (showFirst6 ? first6.length() : 0);
        StringBuilder sb = new StringBuilder(totalLength);
        if (showFirst6) {
            sb.append(first6);
        }
        sb.append(String.valueOf(MASK_CHAR).repeat(Math.max(0, middleLen)));
        sb.append(last4);
        return sb.toString();
    }
}
