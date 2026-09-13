package com.example.pantoken.crypto;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TokenGeneratorTest {

    private final TokenGenerator generator = new TokenGenerator();

    @Test
    void tokensHaveExpectedPrefixAndUrlSafeCharset() {
        String token = generator.generate();
        assertTrue(token.startsWith("tok_"));
        assertTrue(token.matches("tok_[A-Za-z0-9_-]+"));
        assertFalse(token.contains("+"));
        assertFalse(token.contains("/"));
        assertFalse(token.contains("="));
    }

    @Test
    void generatesUniqueTokensAtScale() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 10_000; i++) {
            assertTrue(tokens.add(generator.generate()), "Duplicate token generated");
        }
    }
}
