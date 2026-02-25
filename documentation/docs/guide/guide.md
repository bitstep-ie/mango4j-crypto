# Guide


## Getting Started
The following instructions detail how to use this library. We use Springboot for our examples but that's an arbitrary
choice, you'll write your application however you want. Mango4j-crypto has very few dependencies and doesn't know what 
you do with your entities after encryption/decryption.
An example entity is as follows:

### Encryption


```java language=java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity(name = "USER_PROFILE")
public class UserProfileEntity {

	@Encrypt
	private transient String pan;

	@Encrypt
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	public String getPan() {
		return pan;
	}

	public void setPan(String pan) {
		this.pan = pan;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getEthnicity() {
		return ethnicity;
	}

	public void setEthnicity(String ethnicity) {
		this.ethnicity = ethnicity;
	}

	@Id
	@Column(name = "ID")
	private String id;

	@Column(name = "FAVOURITE_COLOR")
	private String favouriteColor;

	@Column(name = "ENCRYPTED_DATA")
	@EncryptedData
	private String encryptedData;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}

}
```

> NOTES:
> * Fields marked with @Encrypt will be bundled up into a JSON map, encrypted all at once with the remaining ciphertext
    output set into the field marked with @EncryptedData (which is the only field that would then be persisted by the application)
> * You'll notice that we didn't bother defining getters/setters for the ENCRYPTED_DATA field. 
>   This keeps the entity clean from the perspective of the outside world. Code outside this class only has access to 
>   the source fields which will contain the original values. There's usually not a need for outside code to see the actual encrypted values.
> * Notice that the source fields are marked transient. This is a requirement and provides more safety to your application by 
>   making sure that serialization frameworks (Jackson, Hibernate, etc.) discard these values during serialization. 
>   The last thing you want is your ORM flushing confidential values in cleartext to the DB.
> * The favouriteColour field isn't confidential so it's just a plain old field that we define normally, it gets its own 
>   column in the DB, etc.



### CryptoKey Provider

Before we enable mango4j-crypto to encrypt/decrypt our UserProfile entity we need to create our implementation of the 
[CryptoKeyProvider](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/providers/CryptoKeyProvider.java) 
interface for our application. If you store your CryptoKey objects in a database it might look something like this:

```java language=java
package ie.bitstep.mango.examples.crypto.example.common;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.example.domain.entities.CryptoKeyEntity;
import ie.bitstep.mango.examples.crypto.example.repositories.CryptoKeyRepository;
import ie.bitstep.mango.examples.crypto.example.utils.CryptoKeyUtils;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ApplicationCryptoKeyProvider implements CryptoKeyProvider {

	private final CryptoKeyRepository cryptoKeyRepository;
	private final CryptoKeyUtils cryptoKeyUtils;

	public ApplicationCryptoKeyProvider(CryptoKeyRepository cryptoKeyRepository, CryptoKeyUtils cryptoKeyUtils) {
		this.cryptoKeyRepository = cryptoKeyRepository;
		this.cryptoKeyUtils = cryptoKeyUtils;
	}

	@Override
	public CryptoKey getById(String id) {
		CryptoKeyEntity cryptoKeyEntity = cryptoKeyRepository.findById(id).orElseThrow(RuntimeException::new);
		return cryptoKeyUtils.convert(cryptoKeyEntity);
	}

	@Override
	public CryptoKey getCurrentEncryptionKey() {
		return cryptoKeyUtils.convert(cryptoKeyRepository.findTopByUsageOrderByCreatedDateDesc(CryptoKeyUsage.ENCRYPTION));
	}

	@Override
	public List<CryptoKey> getCurrentHmacKeys() {
		return cryptoKeyRepository.findAllByUsage(CryptoKeyUsage.HMAC).stream()
		        .filter(cryptoKeyEntity -> cryptoKeyEntity.getStatus() != DELETED)
		        .map(cryptoKeyUtils::convert)
		        .collect(Collectors.toList());
	}

	@Override
	public List<CryptoKey> getAllCryptoKeys() {
		return cryptoKeyRepository.findAll().stream()
				.filter(cryptoKeyEntity -> cryptoKeyEntity.getStatus() != DELETED)
				.map(cryptoKeyUtils::convert)
				.collect(Collectors.toList());
	}

}
```

> **NOTES**:
> * The getCurrentKey() method should return the currently active encryption key for your tenant/application. 
>   It is called from the CryptoShield.encrypt() method to get the key it should use for the encryption (if applicable).
> * The getCurrentHmacKeys() should return all HMAC keys which are currently in use for your tenant/application. 
>   This is called by CryptoShield.encrypt() and CryptoShield.generateHmacs() to get the key(s) it should use to 
>   calculate HMACs.
> * This example uses the concept of statuses on the keys to keep track of which ones have been deleted. 
>   This allows us to keep the key for a certain length of time after a rekey (and subsequent key deletion) and then 
>   manually clean them up when we're 100% sure we don't need them. Copying this approach is up to you.
> * The getById() method should return the CryptoKey regardless of its status. This method is called for the 
>   CryptoShield.decrypt() method to get the key needed to decrypt the entity.
> * Make sure the createdDate fields on your CryptoKeys are correctly populated.
> * Most CryptoKeys fields are read-only. The only fields that you should ever update are CryptoKey.lastModifiedDate and 
>   CryptoKey.rekeyMode. Don't update the other fields!

### CryptoShield Setup
* Finally we just need to create an instance (bean) for CryptoShield in your application config, passing in a list of all your application
  entities which use @Encrypt or @Hmac, like the following:

```java language=java

@Bean
public CryptoShield cryptoShield(CryptoKeyProvider cryptoKeyProvider) {
	return new CryptoShield.Builder()
			.withCryptoKeyProvider(cryptoKeyProvider)
			.withAnnotatedEntities(List.of(UserProfileEntity.class))
			.withEncryptionServiceDelegates(List.of(new Base64EncryptionService(), new IdentityEncryptionService()))
			.withObjectMapperFactory(new ConfigurableObjectMapperFactory())
			.build();
}
```

> **NOTES:** 
> * In this example we're passing in instances of Base64EncryptionService and IdentityEncryptionService to make
> them available to the library. These come with the library for test purposes and should never be available in a production deployment.
> To minimise this risk it's advised to have separate config classes which run with 'prod' and 'dev'
> profiles. You can create your own EncryptionService classes by creating your own subclass of EncryptionServiceDelegate
> (just like Base64EncryptionService and IdentityEncryptionService do) which
> carries out encryption operations using a cryptographic provider that you use in whatever way you need.
> * We register our UserProfile entity (and any others) with the library using the withAnnotationEntities() method.
> * ConfigurableObjectMapperFactory is a default implementation of
>   [ObjectMapperFactory](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/factories/ObjectMapperFactory.java) 
>   that comes with the library to provide a Jackson ObjectMapper that it can use for formatting and parsing of the ciphertext. 
>   You can supply your own ObjectMapperFactory implementation instead if needed.

Then your application code can encrypt your entities by calling:

```java language=java
        cryptoShield.encrypt(userProfile);
```
And this will encrypt all the confidential fields in your entity and set the resulting ciphertext into the field marked 
with @EncryptedData. 
> **NOTE:** This encrypt operation doesn't affect the original values of the transient fields, they remain exactly as they 
> were (unencrypted). So you can continue working with them in your code after calling CryptoShield.encrypt(). 

<br>
Likewise, to decrypt an entity you can call:

```java language=java
        cryptoShield.decrypt(userProfile);
```

And this will reset all the confidential (transient) fields in your entity back to their original values.

## Key Rotation
Key rotation is almost fairly straightforward when you just think of it as an additive process. A new encryption or HMAC key is 
added to the system but the old keys are left as they are. Only when no more records are left which were encrypted, or 
has had HMACs calculated, with an older key should that key be removed from the system. As long as your 
CryptoKeyProvider implementation works as prescribed then things should be fine. 
[But make sure you understand how HMACs are different](/documentation/docs/general/general.md#hmac-key-rotation-challenges)...

## Rekeying
Mango4j-crypto has built in support for rekey jobs (currently in BETA). Encryption rekeying is supported for all 
entities but for HMACs the RekeyScheduler currently only supports rekeying HMACs for entities which use the List HMAC 
Strategy. The configuration is as follows:


1. Implement the RekeyCryptoKeyManager interface and configure an instance of it.
2. For each entity that uses this library create a corresponding implementation of the RekeyService interface.
3. Configure a RekeyScheduler in your config class, like so:

```java language=java

@Bean
public RekeyScheduler rekeyScheduler(CryptoShield cryptoShield,
                                     List<RekeyService<?>> rekeyServices,
                                     RekeyCryptoKeyManager rekeyCryptoKeyManager,
                                     ObjectMapperFactory objectMapperFactory,
                                     Clock clock) {
	RekeySchedulerConfig rekeySchedulerConfig = RekeySchedulerConfig.builder()
			// Mandatory configurations
			.withCryptoShield(cryptoShield)
			.withRekeyServices(rekeyServices)
			.withRekeyCryptoKeyManager(rekeyCryptoKeyManager)
			.withObjectMapper(objectMapperFactory.objectMapper())
			.withClock(clock)
			.withCryptoKeyCachePeriod(Duration.ofMinutes(60)) // IMPORTANT: Set to your key cache duration
			.withRekeyCheckInterval(1, 24, TimeUnit.HOURS) // Check for re-key jobs once a day, starting after 1 hour

			// Optional configurations
			.withBatchInterval(Duration.ofSeconds(1)) // Pause 1 second between batches
			.withMaximumToleratedFailuresPerExecution(50)
			.build();
	return new RekeyScheduler(rekeySchedulerConfig);
}
```

The above is a once off config. Once done, it allows the application to perform rekey jobs with no extra code and
without
restarting the application. In order to make this periodic RekeyScheduler start rekeying entities you need to make use
of
the CryptoKey.rekeyMode field. Mango4j-crypto supports 2 types of rekey modes: KEY_OFF and KEY_ON. Please see the
[general documentation](general/general.md#rekeying-re-encrypting-existing-records-with-the-new-key) 
for an explanation of these values. Once the CryptoKey.rekeyMode field is set to either
KEY_ON or KEY_OFF this RekeyScheduler will trigger the rekeying process the next time it runs (defined by
`withRekeyCheckInterval()` as above).

> NOTE: You can still use the RekeyScheduler to configure a rekey for any entity that only has @Encrypt fields (and
> doesn't have HMACs). It's just that HMAC rekey is currently only supported for entities that use the List HMAC Strategy.



## Encryption Service Delegates
Mango4J Crypto uses pluggable Encryption Service Delegates to carry out cryptographic operations at runtime. There are several encryption service delegates currently supported (and more to come). Please see the 
[delegates section](delegates/index.md) for documentation on each. 

You can also create your own EncryptionServiceDelegate implementations by subclassing the
[EncryptionServiceDelegate](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/EncryptionServiceDelegate.java) class and
implementing the abstract methods with your own logic using your cryptographic provider of choice.