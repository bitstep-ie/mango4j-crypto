# mango4j-crypto

## Overview
Annotation-driven encryption and HMAC for Java entities.

## Architecture
- `CryptoShield` orchestrates encrypt/decrypt for annotated entities.
- `AnnotatedEntityManager` registers fields and strategy metadata.
- HMAC strategies determine how HMACs are stored and rotated.

## How to use
### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto:VERSION")
```

### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto</artifactId>
    <version>VERSION</version>
</dependency>
```

## More
- [Base documentation](mango4j-crypto/basic.md)
