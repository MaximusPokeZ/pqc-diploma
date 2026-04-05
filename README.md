# `pqc-diploma`

Библиотека для гибридной постквантовой защиты данных в Spring Boot и Java-приложениях.

Проект объединяет классическую криптографию и PQC-алгоритмы NIST:

- KEM: `X25519` / `SECP256R1` + `ML-KEM`
- Подписи: `ML-DSA`
- Режимы: `HYBRID`, `PQC_ONLY`, `CLASSICAL_ONLY`

## Модули

1. `pqc-crypto-core`  
   Чистое криптографическое ядро без Spring.  
   Подробнее: [`pqc-crypto-core/README.md`](pqc-crypto-core/README.md)

2. `pqc-spring-boot-autoconfigure`  
   Автоконфигурация Spring Boot и биндинг `pqc.*` настроек.  
   Подробнее: [`pqc-spring-boot-autoconfigure/README.md`](pqc-spring-boot-autoconfigure/README.md)

3. `pqc-hybrid-spring-boot-starter`  
   Финальный starter-модуль для подключения одной зависимостью.  
   Подробнее: [`pqc-hybrid-spring-boot-starter/README.md`](pqc-hybrid-spring-boot-starter/README.md)

## Быстрый старт

```kotlin
implementation("io.github.mzaslav.pqc:pqc-hybrid-spring-boot-starter:<version>")
```

```yaml
pqc:
  encryption:
    mode: HYBRID
  signature:
    pqc-algorithm: ML_DSA_65
```