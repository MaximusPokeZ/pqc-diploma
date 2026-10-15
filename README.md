# `pqc-hybrid`

A Java 25 library and Spring Boot starter for **hybrid post-quantum cryptography**: every encryption and signature operation combines a classical algorithm with a NIST-standardised post-quantum algorithm so that ciphertexts and signatures remain secure as long as **at least one** of the two underlying primitives stays unbroken.

The project is the practical part of an undergraduate thesis on *"long-term secure storage of digital assets using hybrid post-quantum cryptographic algorithms on the Java 25 platform"*. The contribution is the hybrid construction itself – key encapsulation and signatures that defend against both classical and "harvest now, decrypt later" quantum adversaries – packaged as a drop-in Spring Boot starter.

## Thesis

- [Thesis (PDF, in Russian)](docs/thesis.pdf)
- [Defense presentation (PDF, in Russian)](docs/presentation.pdf)

## What's in the box

| Primitive | Classical | Post-quantum (NIST FIPS) | Combiner |
| --- | --- | --- | --- |
| **KEM** (encryption) | X25519, secp256r1 | ML-KEM-512 / 768 / 1024 (FIPS 203) | HKDF-SHA256 |
| **Signature** | Ed25519, ECDSA P-256, RSA-2048 | ML-DSA-44 / 65 / 87 (FIPS 204) | dual-verify (both must validate) |
| **AEAD** | AES-256-GCM | – | – |
| **Compression (optional)** | GZIP, ZSTD, LZ4, Fourier | – | – |

Three operating modes are available for both KEM and signature primitives: `HYBRID` (default), `PQC_ONLY`, `CLASSICAL_ONLY`.

## Modules

| Module | Purpose |
| --- | --- |
| [`pqc-crypto-core`](pqc-crypto-core/README.md) | Pure-Java crypto core: hybrid KEM, hybrid signatures, AEAD, compression. No Spring dependency. |
| [`pqc-spring-boot-autoconfigure`](pqc-spring-boot-autoconfigure/README.md) | Spring Boot auto-configuration that builds `HybridEncryptor` / `HybridSigner` beans from `pqc.*` properties. |
| [`pqc-hybrid-spring-boot-starter`](pqc-hybrid-spring-boot-starter/README.md) | Aggregating starter – the only dependency a Spring Boot consumer needs. |
| [`pqc-demo-app`](pqc-demo-app/README.md) | Reference Spring Boot app with REST endpoints, Prometheus metrics and a Grafana dashboard for benchmarking the schemes. |

## Quick start

Add the starter to a Spring Boot 4 project:

```kotlin
implementation("io.github.mzaslav.pqc:pqc-hybrid-spring-boot-starter:1.0-SNAPSHOT")
```

Configure in `application.yml`:

```yaml
pqc:
  encryption:
    mode: HYBRID
    pqc-algorithm: ML_KEM_768
    classical-algorithm: X25519
    compression:
      enabled: true
      algorithm: ZSTD
  signature:
    mode: HYBRID
    pqc-algorithm: ML_DSA_65
    classical-algorithm: ED25519
```

Inject and use:

```java
@Autowired HybridEncryptor encryptor;
@Autowired HybridSigner    signer;

try (KemKeyPair kp = encryptor.generateKeyPair()) {
    EncryptedMessage msg = encryptor.encrypt(kp.getEncodedPublicKey(), payload);
    byte[] plaintext = encryptor.decrypt(kp, msg);
}

SignatureKeyPair sk = signer.generateKeyPair();
byte[] sig = signer.sign(sk, payload);
boolean ok = signer.verify(sk, payload, sig);
```

## Requirements

- **Java 25+** – the library relies on JEP 496 (ML-KEM) and JEP 497 (ML-DSA) shipped with the JDK; no BouncyCastle is required.
- **Spring Boot 4.0.x** for the starter / autoconfigure modules.
- **Gradle 8+** to build from source.

## Build

```bash
./gradlew build
```

Run the demo (Prometheus + Grafana included) from `pqc-demo-app`:

```bash
cd pqc-demo-app
./gradlew bootJar
docker compose up
```

The demo exposes:
- REST API on `:8080`
- Prometheus on `:9090`
- Grafana on `:3000` (admin/admin)

## Project layout

```
PQC-HYBRID/
├── docs/                            # thesis and presentation (PDF)
├── pqc-crypto-core/                 # core library (no Spring)
├── pqc-spring-boot-autoconfigure/   # @AutoConfiguration + @ConfigurationProperties
├── pqc-hybrid-spring-boot-starter/  # aggregating starter
└── pqc-demo-app/                    # demo + benchmarks + observability
```

## License

Academic project. See individual module documentation for details.
