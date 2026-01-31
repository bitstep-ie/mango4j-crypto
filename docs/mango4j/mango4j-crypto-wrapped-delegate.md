# mango4j-crypto-wrapped-delegate

## Overview
Encryption delegates that use wrapped data-encryption keys (DEKs).

## Included delegates
- `WrappedKeyEncryptionService` for per-payload DEK wrapping.
- `CachedWrappedKeyEncryptionService` for cached DEKs with TTL and secure destruction.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto-wrapped-delegate:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-wrapped-delegate</artifactId>
    <version>VERSION</version>
</dependency>
```
