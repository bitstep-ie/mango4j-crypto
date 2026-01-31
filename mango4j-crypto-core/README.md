# mango4j-crypto-core

[Back to root README](../readme.md)

Core crypto abstractions shared across mango4j crypto modules.

## Architecture
- Domain objects: `CryptoKey`, `CryptoKeyUsage`, `CiphertextContainer`, `HmacHolder`.
- Orchestration: `EncryptionService` routes operations to `EncryptionServiceDelegate` implementations based on key type.
- Formatting: `CiphertextFormatter` serializes and parses stored ciphertext JSON.
- Key lookup: `CryptoKeyProvider` supplies active keys for encryption and HMAC.
- Object mapping: `ObjectMapperFactory` and `ConfigurableObjectMapperFactory` (limits JSON string length).
- Enums/utilities: `Algorithm`, `Mode`, `Padding`, and `Generators` for IV/random data.

## Functionality
- Encrypt/decrypt using pluggable delegates.
- Batch encryption support (delegate override).
- HMAC calculation grouped by delegate for key rotation scenarios.
- Standard ciphertext storage format: `{ "cryptoKeyId": "...", "data": { ... } }`.

## Usage
### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-core</artifactId>
    <version>VERSION</version>
</dependency>
```

### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto-core:VERSION")
```

## Examples
### Wiring an EncryptionService
```java
ObjectMapperFactory mapperFactory = new ConfigurableObjectMapperFactory();
CryptoKeyProvider provider = new MyCryptoKeyProvider();
CiphertextFormatter formatter = new CiphertextFormatter(provider, mapperFactory);

List<EncryptionServiceDelegate> delegates = List.of(new MyEncryptionServiceDelegate());
EncryptionService service = new EncryptionService(delegates, formatter, mapperFactory);

CryptoKey key = provider.getCurrentEncryptionKey();
CiphertextContainer container = service.encrypt(key, "hello");
String stored = formatter.format(container);

String clear = service.decrypt(stored);
```

```java
class MyEncryptionServiceDelegate extends EncryptionServiceDelegate {
    @Override
    public String supportedCryptoKeyType() { return "MY_TYPE"; }

    @Override
    public CiphertextContainer encrypt(CryptoKey encryptionKey, String data) {
        return new CiphertextContainer(encryptionKey, Map.of("cipherText", data));
    }

    @Override
    public String decrypt(CiphertextContainer ciphertextContainer) {
        return (String) ciphertextContainer.getData().get("cipherText");
    }

    @Override
    public void hmac(Collection<HmacHolder> hmacHolders) {
        // implement as needed
    }
}
```

### Implementing a CryptoKeyProvider
```java
class MyCryptoKeyProvider implements CryptoKeyProvider {
    @Override
    public CryptoKey getById(String cryptoKeyId) { return loadKey(cryptoKeyId); }

    @Override
    public CryptoKey getCurrentEncryptionKey() { return loadCurrentEncryptionKey(); }

    @Override
    public List<CryptoKey> getCurrentHmacKeys() { return loadCurrentHmacKeys(); }

    @Override
    public List<CryptoKey> getAllCryptoKeys() { return loadAllKeys(); }
}
```
