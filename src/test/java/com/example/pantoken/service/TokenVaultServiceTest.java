package com.example.pantoken.service;

import com.example.pantoken.crypto.AesGcmCipherService;
import com.example.pantoken.crypto.KeyProvider;
import com.example.pantoken.crypto.TokenGenerator;
import com.example.pantoken.exception.InvalidPanException;
import com.example.pantoken.exception.TokenNotFoundException;
import com.example.pantoken.exception.UnauthorizedDetokenizationException;
import com.example.pantoken.model.TokenRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenVaultServiceTest {

    private TokenVaultService vault;

    @BeforeEach
    void setUp() {
        vault = new TokenVaultService(new KeyProvider(), new AesGcmCipherService(), new TokenGenerator());
    }

    @Test
    void tokenizeReturnsOpaqueTokenAndSafeMetadataOnly() {
        TokenRecord record = vault.tokenize("4111 1111 1111 1111");

        assertNotNull(record.getToken());
        assertTrue(record.getToken().startsWith("tok_"));
        assertEquals("1111", record.getLast4());
        assertEquals("VISA", record.getBrand());
        // Nothing about the record's public accessors exposes the raw PAN.
        assertFalse(record.toString().contains("4111111111111111"));
    }

    @Test
    void tokenizeRejectsInvalidPan() {
        assertThrows(InvalidPanException.class, () -> vault.tokenize("not-a-card-number"));
    }

    @Test
    void maskedPanNeverExposesFullNumber() {
        TokenRecord record = vault.tokenize("4111111111111111");

        String masked = vault.maskedPan(record.getToken(), false);
        assertEquals("************1111", masked);
        assertFalse(masked.contains("411111111111"));
    }

    @Test
    void maskedPanCanOptionallyShowFirst6() {
        TokenRecord record = vault.tokenize("4111111111111111");

        String masked = vault.maskedPan(record.getToken(), true);
        assertEquals("411111******1111", masked);
    }

    @Test
    void detokenizeWithoutAuthorizationIsRejected() {
        TokenRecord record = vault.tokenize("4111111111111111");

        assertThrows(UnauthorizedDetokenizationException.class,
                () -> vault.detokenize(record.getToken(), false));
    }

    @Test
    void detokenizeWithAuthorizationReturnsOriginalPan() {
        TokenRecord record = vault.tokenize("4111111111111111");

        String pan = vault.detokenize(record.getToken(), true);
        assertEquals("4111111111111111", pan);
    }

    @Test
    void unknownTokenRaisesNotFound() {
        assertThrows(TokenNotFoundException.class, () -> vault.maskedPan("tok_does_not_exist", false));
        assertThrows(TokenNotFoundException.class, () -> vault.detokenize("tok_does_not_exist", true));
    }

    @Test
    void revokeRemovesTokenPermanently() {
        TokenRecord record = vault.tokenize("4111111111111111");
        assertTrue(vault.revoke(record.getToken()));

        assertThrows(TokenNotFoundException.class, () -> vault.maskedPan(record.getToken(), false));
        assertFalse(vault.revoke(record.getToken())); // already gone
    }

    @Test
    void sameCardTokenizedTwiceProducesDifferentTokens() {
        TokenRecord first = vault.tokenize("4111111111111111");
        TokenRecord second = vault.tokenize("4111111111111111");

        assertNotEquals(first.getToken(), second.getToken());
    }
}
