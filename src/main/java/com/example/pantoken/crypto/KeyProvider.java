package com.example.pantoken.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Stands in for a KMS/HSM. Keys never leave this process, are never written
 * to disk, and are never logged. In production this would instead call out
 * to AWS KMS, GCP KMS, HashiCorp Vault, or a real HSM and this class would
 * hold nothing but a client handle.
 *
 * Supports multiple key "versions" so that key rotation can be demonstrated:
 * old ciphertext keeps working (decrypt looks the version up) while new
 * writes always use the current version.
 */
public final class KeyProvider {

    public static final String PROVIDER = "BC";
    public static final String ALGORITHM = "AES";
    private static final int KEY_SIZE_BITS = 256;

    static {
        // Register BouncyCastle once, explicitly, as required by the task brief.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final Map<Integer, SecretKey> keysByVersion = new ConcurrentHashMap<>();
    private final AtomicInteger currentVersion = new AtomicInteger(0);

    public KeyProvider() {
        rotate(); // start with one active key (version 1)
    }

    /** Generates a brand-new AES-256 key and makes it the active signing/encryption version. */
    public synchronized int rotate() {
        int version = currentVersion.incrementAndGet();
        keysByVersion.put(version, generateAesKey());
        return version;
    }

    public int currentVersion() {
        return currentVersion.get();
    }

    public SecretKey keyForVersion(int version) {
        SecretKey key = keysByVersion.get(version);
        if (key == null) {
            throw new IllegalStateException("Unknown key version: " + version
                    + " (has this record's key been destroyed/rotated out?)");
        }
        return key;
    }

    private static SecretKey generateAesKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
            keyGen.init(KEY_SIZE_BITS);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException("Unable to initialize AES key generator", e);
        }
    }
}
