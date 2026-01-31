# mango4j-crypto-wrapped-delegate

[Back to root README](../readme.md)

Encryption delegates that use wrapped data-encryption keys (DEKs).

## Architecture
- `WrappedKeyEncryptionService`: generates a per-payload DEK, encrypts it with a wrapping key (KEK), and stores the wrapped DEK alongside ciphertext.
- `CachedWrappedKeyEncryptionService`: caches wrapped DEKs in-memory with TTL and secure destruction via `CachedWrappedKeyHolder`.
- `InMemoryKeyVault`: stores cached key material encrypted under a vault key.
- `CipherManager`, `CipherConfig`, `CryptoKeyConfiguration`, `EncryptedDataConfig`: model cipher settings and runtime configuration.
- `WrappedCryptoKeyTypes`: key type constants for wrapped delegates.

## Functionality
- Supports AES CBC/GCM with configurable key sizes and IV lengths.
- Standard ciphertext format includes wrapped DEK and cipher parameters.
- Cached delegate reuses DEKs for performance while ensuring key destruction.

## Usage
### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-wrapped-delegate</artifactId>
    <version>VERSION</version>
</dependency>
```

### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto-wrapped-delegate:VERSION")
```

## Examples
### WrappedKeyEncryptionService
```java
CryptoKey key = new CryptoKey();
key.setId("wrapped-key");
key.setType(WrappedCryptoKeyTypes.WRAPPED.getName());
key.setUsage(CryptoKeyUsage.ENCRYPTION);
key.setConfiguration(Map.of(
    "keyEncryptionKey", "kek-id",
    "keySize", 256,
    "ivSize", 12,
    "algorithm", "AES",
    "mode", "GCM",
    "padding", "NoPadding",
    "gcmTagLength", 128
));

CiphertextFormatter formatter = new CiphertextFormatter(cryptoKeyProvider, new ConfigurableObjectMapperFactory());
EncryptionServiceDelegate delegate = new WrappedKeyEncryptionService(cryptoKeyProvider, formatter);
```

### CachedWrappedKeyEncryptionService
```java
EncryptionServiceDelegate delegate = new CachedWrappedKeyEncryptionService(
    Duration.ofMinutes(15),
    Duration.ofHours(24),
    Duration.ofSeconds(5),
    cryptoKeyProvider,
    formatter
);
```

## Notes
- `WrappedKeyEncryptionService` does not implement HMAC operations.
- Configure the KEK in your `CryptoKeyProvider` so the delegate can resolve `keyEncryptionKey`.
