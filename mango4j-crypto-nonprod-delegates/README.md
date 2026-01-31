# mango4j-crypto-nonprod-delegates

[Back to root README](../readme.md)

Non-production `EncryptionServiceDelegate` implementations for local dev and testing.

## Architecture
- `IdentityEncryptionService`: no-op encryption for debugging.
- `Base64EncryptionService`: base64-encodes data and HMAC values.
- `PBKDF2EncryptionService`: PBKDF2-based AES encryption and HMAC (config-driven).
- `NonProdCryptoKeyTypes`: key type constants used by these delegates.

## Functionality
- Simple delegates to exercise `mango4j-crypto-core` and `mango4j-crypto` flows without real KMS/HSM integration.
- PBKDF2 implementation supports AES + CBC/GCM and configurable key size/iterations.

## Usage
### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-nonprod-delegates</artifactId>
    <version>VERSION</version>
</dependency>
```

### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto-nonprod-delegates:VERSION")
```

## Examples
### Base64 delegate
```java
CryptoKey key = new CryptoKey();
key.setId("dev-key");
key.setType(NonProdCryptoKeyTypes.BASE_64.getName());
key.setUsage(CryptoKeyUsage.ENCRYPTION);

EncryptionService service = new EncryptionService(
    List.of(new Base64EncryptionService()),
    cryptoKeyProvider
);

CiphertextContainer container = service.encrypt(key, "hello");
```

### PBKDF2 delegate configuration
```java
CryptoKey key = new CryptoKey();
key.setId("pbkdf2-key");
key.setType(NonProdCryptoKeyTypes.PBKDF2.getName());
key.setUsage(CryptoKeyUsage.ENCRYPTION);
key.setConfiguration(Map.of(
    "keySize", 256,
    "algorithm", "AES",
    "mode", "GCM",
    "padding", "NoPadding",
    "iterations", 65536,
    "gcmTagLength", 128,
    "passPhrase", "local-dev-secret",
    "ivSize", 12,
    "salt", "local-dev-salt"
));
```

## Notes
- These delegates are intended for non-production environments only.
