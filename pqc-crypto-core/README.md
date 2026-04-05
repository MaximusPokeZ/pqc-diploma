# `pqc-crypto-core`

Ядро библиотеки `pqc-diploma`: чистая Java-реализация гибридной и постквантовой криптографии без зависимостей на Spring.

## Что внутри

- Гибридный KEM: классика + ML-KEM (`HybridEncryptor`)
- Режимы шифрования: `HYBRID`, `PQC_ONLY`, `CLASSICAL_ONLY`
- Поддержка классических KEM: `X25519`, `SECP256R1`
- Подписи на ML-DSA (`HybridSigner`)
- Компрессия данных перед шифрованием (`GZIP`, `ZSTD`, `LZ4`, `FOURIER`)

## Когда использовать

Используйте этот модуль напрямую, если:

- у вас не Spring-проект;
- нужна полная ручная настройка и контроль над API;
- вы строите свою интеграцию поверх ядра.

## Пример

```java
HybridEncryptor encryptor = HybridEncryptor.create();

try (KemKeyPair kp = encryptor.generateKeyPair()) {
    byte[] ciphertext = encryptor.encrypt(kp.getEncodedPublicKey(), "hello".getBytes()).toBytes();
    byte[] plaintext = encryptor.decrypt(kp, ciphertext);
}
```

## Зависимость

```kotlin
implementation("io.github.mzaslav.pqc:pqc-crypto-core:<version>")
```
