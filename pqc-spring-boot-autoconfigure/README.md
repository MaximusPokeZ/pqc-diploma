# `pqc-spring-boot-autoconfigure`

Spring Boot auto-configuration module for [`pqc-crypto-core`](../pqc-crypto-core/README.md). It binds `pqc.*` properties from `application.yml` / `application.properties` and exposes ready-to-inject `HybridEncryptor` and `HybridSigner` beans configured for the requested mode (`HYBRID`, `PQC_ONLY`, `CLASSICAL_ONLY`).

You normally do **not** depend on this module directly – pull in [`pqc-hybrid-spring-boot-starter`](../pqc-hybrid-spring-boot-starter/README.md) instead. Use this module on its own when you are building a custom starter or wiring auto-configuration manually.

## What it does

- Registers `HybridEncryptor` (KEM + AEAD) as a Spring bean.
- Registers `HybridSigner` (digital signature) as a Spring bean.
- Binds and validates configuration via `@ConfigurationProperties(prefix = "pqc")`.
- Selects and attaches a `DataCompressor` to the encryptor when compression is enabled.
- Honours user-defined beans of the same type (`@ConditionalOnMissingBean`), so you can override any of the auto-wired beans.

## Properties

```yaml
pqc:
  encryption:
    enabled: true                    # default true
    mode: HYBRID                     # HYBRID | PQC_ONLY | CLASSICAL_ONLY
    pqc-algorithm: ML_KEM_768        # ML_KEM_512 | ML_KEM_768 | ML_KEM_1024
    classical-algorithm: X25519      # X25519 | SECP256R1
    compression:
      enabled: false                 # default false
      algorithm: NONE                # NONE | GZIP | ZSTD | LZ4 | FOURIER
  signature:
    enabled: true                    # default true
    mode: HYBRID                     # HYBRID | PQC_ONLY | CLASSICAL_ONLY
    pqc-algorithm: ML_DSA_65         # ML_DSA_44 | ML_DSA_65 | ML_DSA_87
    classical-algorithm: ED25519     # ED25519 | ECDSA_P256 | RSA_2048
```

### Validation rules

- `mode = HYBRID` ⇒ both `pqc-algorithm` and `classical-algorithm` are required.
- `mode = PQC_ONLY` ⇒ `pqc-algorithm` is required.
- `mode = CLASSICAL_ONLY` ⇒ `classical-algorithm` is required.
- `compression.enabled = true` ⇒ `compression.algorithm` must be different from `NONE`.

Validation is enforced via `jakarta.validation` and produces clear startup-time error messages.

## How beans are picked

| Property combination | Effect |
| --- | --- |
| `pqc.encryption.enabled = true` (default) | `HybridEncryptor` bean created |
| `pqc.encryption.enabled = false` | No encryptor bean; injection points break unless you provide your own |
| `pqc.signature.enabled = true` (default) | `HybridSigner` bean created |
| `pqc.signature.enabled = false` | No signer bean |
| User-defined bean of the same type already present | Auto-config skips that bean (`@ConditionalOnMissingBean`) |

## When to use this module directly

- You are publishing your own starter that wraps additional concerns on top of `pqc-hybrid` (key persistence, KMS integration, etc.).
- You need fine-grained control over which Spring auto-configurations are imported.

Otherwise prefer the aggregating starter.

## Dependency

```kotlin
implementation("io.github.mzaslav.pqc:pqc-spring-boot-autoconfigure:1.0-SNAPSHOT")
```

The module re-exports `pqc-crypto-core` as `api`, so consumers automatically see the core types.

## Overriding the defaults

```java
@Configuration
class MyCryptoConfig {

    @Bean
    HybridEncryptor customEncryptor() {
        HybridEncryptor encryptor = HybridEncryptor.create(
                ClassicalKemAlgorithm.SECP256R1,
                MlKemParameterSet.ML_KEM_1024);
        encryptor.setCompressor(new ZstdCompressor());
        return encryptor;
    }
}
```

Because the auto-configuration is `@ConditionalOnMissingBean`, the user-defined bean wins.
