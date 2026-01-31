# mango4j-crypto

[Back to root README](../readme.md)

Annotation-driven encryption and HMAC support for Java entities.

## Architecture
- `CryptoShield` is the main entry point, wiring `EncryptionService` and `AnnotatedEntityManager`.
- `AnnotatedEntityManager` registers entity metadata (`@Encrypt`, `@Hmac`, `@EncryptedBlob`, `@EncryptionKeyId`, `@CascadeEncrypt`).
- HMAC strategies (`SingleHmacFieldStrategy`, `DoubleHmacFieldStrategy`, `ListHmacFieldStrategy`, `SingleHmacFieldStrategyForTimeBasedCryptoKey`) are selected via annotations.
- Tokenizers (`HmacTokenizer`, `PanTokenizer`) generate alternative HMAC representations.
- Key rotation: `RekeyCryptoShield`, `RekeyScheduler`, `RekeyService`, and `ProgressTracker` support background re-key operations.

## Functionality
- Encrypt and decrypt annotated entities with a single call.
- Populate encrypted blob and encryption key ID fields.
- Calculate HMACs for lookup and uniqueness strategies.
- Cascade encryption into nested objects/collections.
- Optional serialization helper (`encryptAndSerialize`) to preserve transient values.

## Usage
### Maven
```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto</artifactId>
    <version>VERSION</version>
</dependency>
```

### Gradle
```gradle
implementation("ie.bitstep.mango:mango4j-crypto:VERSION")
```

## Examples
### Annotated entity
```java
@ListHmacStrategy
class Card {
    @Encrypt
    private transient String pan;

    @Hmac(hmacTokenizers = {PanTokenizer.class})
    private transient String panHmac;

    @EncryptedBlob
    private String encryptedData;

    @EncryptionKeyId
    private String encryptionKeyId;
}
```

### CryptoShield wiring
```java
CryptoShield cryptoShield = new CryptoShield.Builder()
    .withAnnotatedEntities(List.of(Card.class))
    .withObjectMapperFactory(new ConfigurableObjectMapperFactory())
    .withCryptoKeyProvider(myCryptoKeyProvider)
    .withEncryptionServiceDelegates(List.of(new Base64EncryptionService()))
    .build();

Card card = new Card();
card.setPan("5105105105105100");

cryptoShield.encrypt(card);
// card.encryptedData and card.encryptionKeyId are populated.

cryptoShield.decrypt(card);
// pan field is restored from encryptedData.
```

Note: `Base64EncryptionService` lives in `mango4j-crypto-nonprod-delegates` and is intended for local dev/testing.

### Cascade encryption
```java
@ListHmacStrategy
class Customer {
    @CascadeEncrypt
    private Profile profile;
}
```
