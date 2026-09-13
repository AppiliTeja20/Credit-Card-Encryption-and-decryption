package com.example.pantoken.service;

import com.example.pantoken.crypto.AesGcmCipherService;
import com.example.pantoken.crypto.KeyProvider;
import com.example.pantoken.crypto.TokenGenerator;
import com.example.pantoken.exception.TokenNotFoundException;
import com.example.pantoken.exception.UnauthorizedDetokenizationException;
import com.example.pantoken.model.EncryptedPan;
import com.example.pantoken.model.TokenRecord;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * The vault. This is the only place raw PANs are allowed to exist, and even
 * here they live only as local variables for the duration of a single
 * encrypt/decrypt call -- never as a field, never in the map, never logged.
 *
 * Storage is a simple in-memory ConcurrentHashMap for this exercise; swap
 * {@link #store} for a real datastore and nothing above this class needs to
 * change, because callers only ever see tokens and masked strings.
 */
public final class TokenVaultService {

    private static final Logger LOG = Logger.getLogger(TokenVaultService.class.getName());

    private final Map<String, TokenRecord> store = new ConcurrentHashMap<>();
    private final KeyProvider keyProvider;
    private final AesGcmCipherService cipherService;
    private final TokenGenerator tokenGenerator;

    public TokenVaultService(KeyProvider keyProvider, AesGcmCipherService cipherService, TokenGenerator tokenGenerator) {
        this.keyProvider = keyProvider;
        this.cipherService = cipherService;
        this.tokenGenerator = tokenGenerator;
    }

    /**
     * Validates, encrypts, and vaults a raw PAN. Returns an opaque token that
     * callers should use everywhere in place of the PAN from this point on.
     */
    public TokenRecord tokenize(String rawPan) {
        String pan = PanValidator.normalizeAndValidate(rawPan);
        String token = tokenGenerator.generate();
        int keyVersion = keyProvider.currentVersion();

        EncryptedPan encryptedPan = cipherService.encrypt(pan, keyProvider.keyForVersion(keyVersion), keyVersion, token);
        String first6 = pan.length() >= 6 ? MaskingUtil.first6(pan) : null;
        String last4 = MaskingUtil.last4(pan);
        String brand = PanValidator.detectBrand(pan);
        int panLength = pan.length();

        TokenRecord record = new TokenRecord(token, encryptedPan, first6, last4, brand, panLength, Instant.now());
        store.put(token, record);

        LOG.info(() -> "Tokenized PAN brand=" + brand + " last4=" + last4 + " token=" + token);
        return record;
    }

    /**
     * Safe for any caller: returns the masked PAN, never the raw digits.
     * Built entirely from the non-sensitive first6/last4 metadata already
     * stored on the record -- this never touches the encrypted PAN or the
     * key provider at all.
     */
    public String maskedPan(String token, boolean showFirst6) {
        TokenRecord record = requireRecord(token);
        boolean canShowFirst6 = showFirst6 && record.getFirst6() != null;
        return MaskingUtil.composeMask(record.getFirst6(), record.getLast4(), record.getPanLength(), canShowFirst6);
    }

    /**
     * Returns the raw PAN. Requires the caller to be explicitly authorized
     * (e.g. an authenticated payment-processing subsystem with a legitimate
     * need, verified upstream by the API layer / auth middleware). Every
     * call is audit-logged with masked data only.
     */
    public String detokenize(String token, boolean callerIsAuthorized) {
        if (!callerIsAuthorized) {
            LOG.warning(() -> "Rejected unauthorized detokenize attempt for token=" + token);
            throw new UnauthorizedDetokenizationException();
        }
        TokenRecord record = requireRecord(token);
        SecretKeyLookup lookup = new SecretKeyLookup(keyProvider, record.getEncryptedPan().getKeyVersion());
        String pan = cipherService.decrypt(record.getEncryptedPan(), lookup.key(), token);

        LOG.info(() -> "Authorized detokenize for token=" + token + " last4=" + record.getLast4());
        return pan;
    }

    public boolean revoke(String token) {
        boolean removed = store.remove(token) != null;
        if (removed) {
            LOG.info(() -> "Revoked token=" + token);
        }
        return removed;
    }

    public TokenRecord metadata(String token) {
        return requireRecord(token);
    }

    private TokenRecord requireRecord(String token) {
        TokenRecord record = store.get(token);
        if (record == null) {
            throw new TokenNotFoundException(token);
        }
        return record;
    }

    /** Tiny helper so key lookup failures produce a clear error site. */
    private record SecretKeyLookup(KeyProvider keyProvider, int version) {
        javax.crypto.SecretKey key() {
            return keyProvider.keyForVersion(version);
        }
    }
}
