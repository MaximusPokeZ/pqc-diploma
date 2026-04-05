# `pqc-hybrid-spring-boot-starter`

Финальный starter-модуль для подключения библиотеки одной зависимостью.

Этот модуль не содержит бизнес-кода: он только подтягивает `pqc-spring-boot-autoconfigure` и `spring-boot-starter`.

## Для чего нужен

- Единая точка входа для клиента
- Минимум ручной конфигурации в приложении
- Транзитивное подключение необходимых модулей

## Подключение

```kotlin
implementation("io.github.mzaslav.pqc:pqc-hybrid-spring-boot-starter:<version>")
```

После подключения можно сразу инжектить:

```java
@Autowired
private HybridEncryptor hybridEncryptor;

@Autowired
private HybridSigner hybridSigner;
```

## Минимальная конфигурация

```yaml
pqc:
  encryption:
    mode: HYBRID
  signature:
    pqc-algorithm: ML_DSA_65
```
