# mango4j-crypto-nonprod-delegates

## Overview
Non-production `EncryptionServiceDelegate` implementations for local development and testing.

## Included delegates
- `IdentityEncryptionService` (no-op).
- `Base64EncryptionService` (base64 encode/decode).
- `PBKDF2EncryptionService` (config-driven AES + HMAC).

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto-nonprod-delegates:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-nonprod-delegates</artifactId>
    <version>VERSION</version>
</dependency>
```

## Notes
These delegates are for non-production environments only.
