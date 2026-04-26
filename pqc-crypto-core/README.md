# `pqc-crypto-core`

Pure-Java core of the `pqc-hybrid` library. Provides the cryptographic primitives – key encapsulation, AEAD encryption, digital signatures and optional payload compression – with **no Spring dependency**. Use this module directly when integrating into a non-Spring application or when building your own framework abstraction on top.

## What's inside

- **Hybrid KEM** (`HybridEncryptor`) – combines a classical KEM (X25519 or secp256r1) with ML-KEM (FIPS 203) and derives a single AES-256 key with HKDF-SHA256.
- **Hybrid signatures** (`HybridSigner`) – combines a classical signer (Ed25519 / ECDSA P-256 / RSA-2048) with ML-DSA (FIPS 204); both component signatures must verify.
- **Modes** – `HYBRID`, `PQC_ONLY`, `CLASSICAL_ONLY` for both KEM and signatures.
- **AEAD** – AES-256-GCM with random 12-byte nonces and 128-bit auth tags.
- **Compression (optional)** – `GZIP`, `ZSTD`, `LZ4`, `FOURIER` plug into `HybridEncryptor` via `setCompressor(...)`.
- **Hardening** – constant-time comparison, secure-wipe of key material, length-prefixed wire format with explicit version byte.

## Why hybrid?

A hybrid KEM stays secure as long as **either** the classical KEM **or** ML-KEM is unbroken. This protects today's ciphertexts against the *Harvest Now, Decrypt Later* threat model: even if a future quantum computer breaks X25519, the ML-KEM half keeps the shared secret safe. Hybrid signatures behave the same way at signing time – an attacker would need to forge in both schemes simultaneously.

## When to use this module directly

- You are not on Spring Boot.
- You need full manual control over key handling, persistence or wire format.
- You are building a different framework integration on top of the core.

For Spring Boot applications, prefer the starter: [`pqc-hybrid-spring-boot-starter`](../pqc-hybrid-spring-boot-starter/README.md).

## Dependency

```kotlin
implementation("io.github.mzaslav.pqc:pqc-crypto-core:1.0-SNAPSHOT")
```

Requires Java 25+ (JEP 496 for ML-KEM, JEP 497 for ML-DSA).

## Examples

### Hybrid encryption (default: X25519 + ML-KEM-768)

```java
HybridEncryptor encryptor = HybridEncryptor.create();

try (KemKeyPair kp = encryptor.generateKeyPair()) {
    EncryptedMessage msg = encryptor.encrypt(kp.getEncodedPublicKey(), "hello".getBytes());
    byte[] plaintext  = encryptor.decrypt(kp, msg);          // -> "hello"
    byte[] serialized = msg.toBytes();                       // wire form
}
```

### Hybrid encryption with compression

```java
HybridEncryptor encryptor = HybridEncryptor.create(MlKemParameterSet.ML_KEM_768);
encryptor.setCompressor(new ZstdCompressor());
```

### Hybrid signature (default: Ed25519 + ML-DSA-65)

```java
HybridSigner signer = HybridSigner.create();
SignatureKeyPair kp = signer.generateKeyPair();

byte[] signature = signer.sign(kp, "important".getBytes());
boolean valid    = signer.verify(kp, "important".getBytes(), signature);
```

### Custom algorithm choices

```java
HybridEncryptor enc = HybridEncryptor.create(
        ClassicalKemAlgorithm.SECP256R1,
        MlKemParameterSet.ML_KEM_1024);

HybridSigner sig = HybridSigner.create(
        ClassicalSigAlgorithm.ECDSA_P256,
        MlDsaParameterSet.ML_DSA_87);
```

### PQC-only / classical-only modes

```java
HybridEncryptor pqcOnly       = HybridEncryptor.createPqcOnly(MlKemParameterSet.ML_KEM_768);
HybridEncryptor classicalOnly = HybridEncryptor.createClassicalOnly(ClassicalKemAlgorithm.X25519);

HybridSigner pqcSigner       = HybridSigner.createPqcOnly(MlDsaParameterSet.ML_DSA_65);
HybridSigner classicalSigner = HybridSigner.createClassicalOnly(ClassicalSigAlgorithm.ED25519);
```

## Wire format

`EncryptedMessage.toBytes()` produces:

```
| Version (1) | KemAlgorithm (1) | CompressionAlgorithm (1) | KEM length (4 BE) | KEM ciphertext | AEAD ciphertext+tag |
```

The AEAD ciphertext itself is `[12-byte nonce] || [GCM ciphertext+tag]`.

Hybrid keys, ciphertexts and signatures all use a length-prefixed concatenation:

```
| len1 (4 BE) | data1 | len2 (4 BE) | data2 |
```

## Package overview

| Package | Role |
| --- | --- |
| `io.mzaslav.pqc.algorithm` | Enums for algorithms and parameter sets (`KemAlgorithm`, `MlKemParameterSet`, `MlDsaParameterSet`, `CryptoMode`, ...) |
| `io.mzaslav.pqc.kem` | KEM providers (`MlKemProvider`, `X25519Provider`, `Secp256r1Provider`, `HybridKemProvider`) |
| `io.mzaslav.pqc.signature` | Signature providers (`MlDsaProvider`, `ClassicalSignatureProvider`, `HybridSignatureProvider`) |
| `io.mzaslav.pqc.hybrid` | High-level facades (`HybridEncryptor`, `HybridSigner`, `HybridCombiner`, `EncryptedMessage`) |
| `io.mzaslav.pqc.encryption` | AEAD (`AeadEncryptor`) |
| `io.mzaslav.pqc.compression` | `DataCompressor` SPI + GZIP / ZSTD / LZ4 / Fourier implementations |
| `io.mzaslav.pqc.exception` | `PqcException` hierarchy |
| `io.mzaslav.pqc.util` | `SecureBytes` – constant-time compare, wipe, secure random |

## Testing

```bash
./gradlew :pqc-crypto-core:test
```

The module includes JUnit 5 tests covering each provider, hybrid round-trips, AEAD authentication, secret combining and compressors.
