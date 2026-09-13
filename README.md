# PAN Encryption & Tokenization Service

Task 5 — Credit Card Encryption & Decryption. A small Java service that safely
encrypts/decrypts card numbers (PANs), issues opaque vault tokens, enforces
masking on every read path, and **never persists a raw PAN** anywhere
(memory, logs, or disk).

## Why it's built this way

**Tokenization, not raw encryption exposure.** A PAN is validated, encrypted,
and immediately replaced with a random, unguessable token (`tok_...`). From
that point on, every other part of the system — logs, other services, this
API's default responses — deals only in tokens and masked strings. The one
raw PAN, at any moment, exists only as a short-lived local variable during a
single encrypt or decrypt call; it is never a field, never put in the vault
map, and never written to a log line.

**AES-256-GCM via an explicit JCE/BouncyCastle provider.** GCM is an
authenticated mode: it gives confidentiality *and* tamper detection in one
step, so a flipped bit in storage fails to decrypt instead of silently
returning corrupted data. A fresh random 96-bit IV is generated per
encryption (IVs must never repeat under the same key). The current vault
**token is bound in as AAD (Additional Authenticated Data)**, so a stored
ciphertext can never be swapped onto a different token's record and still
decrypt successfully.

**Masking is structural, not just a formatting choice.** `MaskingUtil`
builds masked PANs (`************1111` / `411111******1111`) purely from the
non-sensitive `first6` (BIN/IIN) and `last4` fields — both of which PCI DSS
explicitly permits storing in the clear. The masked view never touches the
encrypted PAN or the key provider at all, so there's no code path where a
"just show the mask" request can accidentally decrypt anything.

**Detokenization (getting the raw PAN back) is a distinct, gated operation.**
It requires an explicit authorization signal (in this demo, an
`X-Authorization-Level: PCI_AUTHORIZED` header simulating an upstream
auth/entitlement check) and every attempt — successful or not — is
audit-logged with masked data only.

**Key management is abstracted behind `KeyProvider`.** It stands in for a
real KMS/HSM (AWS KMS, GCP KMS, Vault, etc.) and supports versioned keys, so
rotating to a new key doesn't break decryption of records encrypted under an
older version. In production, `KeyProvider` would hold nothing but a client
handle — the actual key material would never leave the KMS.

**Tokens use Base64URL (RFC 4648 §5).** 192 bits of `SecureRandom` entropy,
encoded so the token is safe to drop directly into JSON, URLs, and headers
with no further escaping (no `+`, `/`, or `=` padding).

### Format-preserving encryption (FPE) — why this demo uses classic tokenization instead

FPE (e.g. FF1/FF3-1, NIST SP 800-38G) encrypts a PAN into ciphertext that is
*itself* a valid-looking card number, preserving length and character set.
That's attractive when downstream systems have rigid PAN-shaped fields they
can't easily change. The trade-off: FF3-1 has known cryptanalytic weaknesses
around tweak reuse and small domains, so real deployments lean on FF1 with
careful tweak management, and the ciphertext is still directly reversible
with the key — there's no separate secret token protecting it. This service
uses **AES-GCM + a random opaque token** instead: the token carries zero
information about the PAN, so a leaked token database alone reveals nothing,
whereas a leaked FPE ciphertext plus key(reversibility) does. For a system
that owns its own schema (as this one does), classic tokenization gives
stronger isolation for similar effort.

## Project layout

```
src/main/java/com/example/pantoken/
  crypto/    KeyProvider, AesGcmCipherService, TokenGenerator
  model/     EncryptedPan, TokenRecord
  service/   PanValidator (Luhn), MaskingUtil, TokenVaultService
  api/       HttpServerApp (embedded REST API), JsonUtil
  exception/ InvalidPanException, TokenNotFoundException, UnauthorizedDetokenizationException
  Main.java
src/test/java/...   JUnit 5 tests for every layer above
```

## Running it

Requires JDK 17+.

**With Maven** (if you have network access to Maven Central):
```
mvn compile exec:java -Dexec.mainClass=com.example.pantoken.Main
# or, after `mvn package`, using the shaded jar:
java -jar target/pan-token-service.jar [port]   # default port 8080
```

**Without Maven**, using distro packages (what was used to build/test this
in the sandbox, since Maven Central wasn't reachable):
```bash
sudo apt-get install -y libbcprov-java libjackson2-databind-java \
    libjackson2-core-java libjackson2-annotations-java junit5 default-jdk-headless

CP="/usr/share/java/bcprov.jar:/usr/share/java/jackson-databind.jar:/usr/share/java/jackson-core.jar:/usr/share/java/jackson-annotations.jar"

javac -cp "$CP" -d out/classes $(find src/main/java -name "*.java")
java  -cp "$CP:out/classes" com.example.pantoken.Main 8080
```

## Running the tests

```bash
CP="/usr/share/java/bcprov.jar:/usr/share/java/jackson-databind.jar:/usr/share/java/jackson-core.jar:/usr/share/java/jackson-annotations.jar"
javac -cp "$CP:out/classes" -d out/test-classes $(find src/test/java -name "*.java")
java -jar /usr/share/java/junit-platform-console-standalone.jar \
    -cp "$CP:out/classes:out/test-classes" --scan-classpath
```
29 tests covering Luhn validation, masking, AES-GCM round-trip/tamper/AAD-binding,
token uniqueness, and the vault's tokenize/mask/detokenize/revoke lifecycle
all pass (verified in this environment since `mvn` could not reach Maven
Central for dependency resolution).

## API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/pan/tokenize` | Body `{"pan": "4111111111111111"}` → `201` with `token`, masked view, `last4`, `brand`. Never returns the raw PAN. |
| `GET` | `/api/pan/{token}/mask?showFirst6=true` | Returns only a masked PAN. No authorization required — this is the safe default. |
| `POST` | `/api/pan/{token}/detokenize` | Requires header `X-Authorization-Level: PCI_AUTHORIZED`. Returns the raw PAN. `403` without it. |
| `DELETE` | `/api/pan/{token}` | Revokes/deletes the vault record. `204` on success, `404` if unknown. |
| `GET` | `/api/pan/validate?pan=...` | Luhn/format check only — never touches the vault or crypto layer. |
| `GET` | `/health` | Liveness check. |

Example:
```bash
curl -X POST localhost:8080/api/pan/tokenize -H 'Content-Type: application/json' \
  -d '{"pan":"4111 1111 1111 1111"}'
# {"token":"tok_...","brand":"VISA","last4":"1111","first6":"411111","maskedPan":"411111******1111",...}

curl localhost:8080/api/pan/tok_.../mask
# {"token":"tok_...","maskedPan":"************1111"}

curl -X POST localhost:8080/api/pan/tok_.../detokenize -H 'X-Authorization-Level: PCI_AUTHORIZED'
# {"token":"tok_...","pan":"4111111111111111"}
```

## Known limitations of this demo (called out intentionally)

- **Storage is in-memory** (`ConcurrentHashMap`), per the task scope — restarting
  the process loses all tokens. The vault is written so swapping in a real
  datastore only touches `TokenVaultService`'s internal map, not any caller.
- **`KeyProvider` generates its master key in-process** rather than calling
  out to a real KMS/HSM — acceptable for a demo, not for production.
- **Authorization is a single header check**, standing in for a real
  authentication/entitlement system that would sit in front of this service.
- No FPE implementation is included (see rationale above); it would be a
  reasonable follow-up using a vetted library (e.g. BouncyCastle's FPE
  support) if a downstream system truly requires PAN-shaped ciphertext.
