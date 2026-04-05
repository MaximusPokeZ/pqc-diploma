# `pqc-spring-boot-autoconfigure`

Модуль автоконфигурации Spring Boot для `pqc-crypto-core`.

Он создает готовые `Bean`-компоненты (`HybridEncryptor`, `HybridSigner`) на основе `application.yml`/`application.properties`.

## Что делает

- Регистрирует `HybridEncryptor` и `HybridSigner` автоматически
- Биндинг свойств из префикса `pqc.*`
- Валидация конфигурации через `jakarta.validation`
- Подключение компрессора для шифрования по настройкам

## Основные свойства

```yaml
pqc:
  encryption:
    enabled: true
    mode: HYBRID            # HYBRID | PQC_ONLY | CLASSICAL_ONLY
    pqc-algorithm: ML_KEM_768
    classical-algorithm: X25519
    compression:
      enabled: false
      algorithm: NONE       # NONE | GZIP | ZSTD | LZ4 | FOURIER
  signature:
    enabled: true
    mode: HYBRID
    pqc-algorithm: ML_DSA_65
    classical-algorithm: ED25519
```

## Когда использовать

Используйте этот модуль, если вы делаете собственный starter или хотите подключать автоконфигурацию отдельно, без агрегирующего starter.

## Зависимость

```kotlin
implementation("io.github.mzaslav.pqc:pqc-spring-boot-autoconfigure:<version>")
```
