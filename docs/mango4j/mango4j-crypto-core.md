# mango4j-crypto-core

## Overview
Core crypto abstractions shared by mango4j crypto modules.

## Architecture
- Domain objects: `CryptoKey`, `CryptoKeyUsage`, `CiphertextContainer`, `HmacHolder`.
- Orchestration: `EncryptionService` routes operations to delegates by key type.
- Formatting: `CiphertextFormatter` serializes and parses stored ciphertext.
- Providers: `CryptoKeyProvider` supplies active keys.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto-core:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-core</artifactId>
    <version>VERSION</version>
</dependency>
```

## More
- [Base documentation](mango4j-crypto-core/basic.md)
