package com.example.pantoken.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MaskingUtilTest {

    @Test
    void masksAllButLast4() {
        assertEquals("************1111", MaskingUtil.maskShowLast4("4111111111111111"));
    }

    @Test
    void masksShowingFirst6AndLast4() {
        assertEquals("411111******1111", MaskingUtil.maskShowFirst6Last4("4111111111111111"));
    }

    @Test
    void composeMaskMatchesDirectMaskWhenShowingFirst6() {
        String direct = MaskingUtil.maskShowFirst6Last4("4111111111111111");
        String composed = MaskingUtil.composeMask("411111", "1111", 16, true);
        assertEquals(direct, composed);
    }

    @Test
    void composeMaskMatchesDirectMaskWhenHidingFirst6() {
        String direct = MaskingUtil.maskShowLast4("4111111111111111");
        String composed = MaskingUtil.composeMask(null, "1111", 16, false);
        assertEquals(direct, composed);
    }

    @Test
    void extractsLast4AndFirst6() {
        assertEquals("1111", MaskingUtil.last4("4111111111111111"));
        assertEquals("411111", MaskingUtil.first6("4111111111111111"));
    }

    @Test
    void neverThrowsForVeryShortInputInsteadFullyMasks() {
        assertEquals("***", MaskingUtil.maskShowLast4("123"));
    }
}
