# `pqc-hybrid-spring-boot-starter`

Aggregating Spring Boot starter for the `pqc-hybrid` library. This is the **only** dependency a Spring Boot consumer needs to add. The module ships no business logic of its own – it transitively pulls in [`pqc-crypto-core`](../pqc-crypto-core/README.md), [`pqc-spring-boot-autoconfigure`](../pqc-spring-boot-autoconfigure/README.md) and `spring-boot-starter`.

## Why a starter

- **Single point of entry** for application developers.
- **Zero ceremony** – no manual `@Import`, no `@EnableXxx`.
- **Sensible defaults** – hybrid mode with X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65 work out of the box.
- **Override-friendly** – every auto-configured bean is `@ConditionalOnMissingBean`, so providing your own implementation is one `@Bean` away.

## Getting started

Add the starter:

```kotlin
implementation("io.github.mzaslav.pqc:pqc-hybrid-spring-boot-starter:1.0-SNAPSHOT")
```

Inject the auto-wired beans:

```java
@Service
@RequiredArgsConstructor
public class SecureStorage {

    private final HybridEncryptor encryptor;
    private final HybridSigner    signer;

    public byte[] seal(byte[] payload, byte[] recipientPubKey) {
        return encryptor.encrypt(recipientPubKey, payload).toBytes();
    }

    public byte[] sign(SignatureKeyPair kp, byte[] payload) {
        return signer.sign(kp, payload);
    }
}
```

## Minimal configuration

```yaml
pqc:
  encryption:
    mode: HYBRID
  signature:
    mode: HYBRID
    pqc-algorithm: ML_DSA_65
```

A full reference of all available properties lives in the [`pqc-spring-boot-autoconfigure` README](../pqc-spring-boot-autoconfigure/README.md#properties).

## What it pulls in

```
pqc-hybrid-spring-boot-starter
  ├── pqc-crypto-core                 (the actual cryptography)
  ├── pqc-spring-boot-autoconfigure   (binds pqc.* properties → beans)
  └── spring-boot-starter             (logging, externalized config, ...)
```

## Requirements

- Java 25+ (ML-KEM and ML-DSA are provided by the JDK – no BouncyCastle).
- Spring Boot 4.0.x.

## Looking for the demo?

A reference application with REST endpoints, Prometheus metrics and a Grafana dashboard lives in [`pqc-demo-app`](../pqc-demo-app/README.md).
