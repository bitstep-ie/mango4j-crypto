# mango4j-crypto {.hidden}

<figure markdown="span">
    ![Logo](../assets/mango-with-text-black.png#only-light)
    ![Logo](./assets/mango-with-text-white.png#only-dark)
    <figcaption>mango4j-crypto</figcaption>
</figure>


# Table Of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Encryption](#encryption)
   1. [CryptoKey Provider](#cryptokey-provider)
   2. [CryptoShield Setup](#cryptoshield-setup)
4. [HMAC](#hmac)
    1. [Single HMAC Strategy](#single-hmac-strategy)
    2. [List HMAC Strategy](#list-hmac-strategy)
       1. [HMAC Tokenizers](#hmac-tokenizers)
       2. [Compound Unique Constraints with the List HMAC Strategy](#compound-unique-constraints-with-the-list-hmac-strategy)
    3. [Single HMAC Strategy With Key Start Time](#single-hmac-strategy-with-key-start-time)
    4. [Double HMAC Strategy](#double-hmac-strategy)
5. [Key Rotation](#key-rotation)
6. [Rekeying](#rekeying)
7. [Provided Encryption Service Delegates](#provided-encryption-service-delegates)
   1. [Testing Delegates](#testing-delegates)
      1. [Base64EncryptionService](#base64-encryption-service-delegate)
      2. [IdentityEncryptionService](#identity-encryption-service-delegate)
   2. [Production Delegates](#production-delegates)
      1. [PBKDF2EncryptionService](#pbkdf2-encryption-service-delegate)
      2. [WrappedKeyEncryptionService](#wrapped-key-encryption-service-delegate)
      3. [CachedWrappedKeyEncryptionService](#cached-wrapped-key-encryption-service-delegate)
      3. [AWS Encryption Service](#aws-encryption-service-delegate)


## Annotations

The main annotations that developers will use are:

### @Encrypt

The @Encrypt annotation should be placed on fields which must be encrypted. This annotation also requires the
@EncryptedData partner annotation to be placed on the (single) field
where the library should put the resulting ciphertext (which is generated in one go for all fields), so you only need
one @EncryptedData field regardless of the number of @Encrypt
fields. This is shown in the example entity code below.

> **NOTE**: All fields marked with @Encrypt must be transient or the library will throw an error on registration of the
> entity. The only exception to this is when also using the @EnabledMigrationSupport annotation during once off
> migration
> onto the library for existing applications (this will be explained further in this document).

### @Hmac

The @Hmac annotation should be placed on fields which must be HMACed for either lookup or unique constraint purposes.
Depending on the HmacStrategy that your entity is using there needs to be corresponding fields where the library should 
write the HMACs to. There are currently 3 HMAC strategies supported by the library and each one has slightly different 
approaches related to the design of your entity. This will most certainly seem strange, but they will be
discussed at length further in this documentation when it will make more sense. Also, if you're familiar with the
challenges mentioned in the [the official Mango4j-crypto general documentation](/documentation/docs/general/general.md)
they will make more sense.

> **NOTE**: All fields marked with @Hmac must be transient or the library will throw an error on registration of the
> entity. The only exception to this is when also using the @EnabledMigrationSupport annotation during once off
> migration onto the library for existing applications (this will be explained further in this document).

### @EncryptedData

As discussed above, if you have any fields marked with @Encrypt then you must have a single field marked with
@EncryptedData where the library will store the ciphertext for all
encrypted source fields. Underneath the hood, the library serializes all original fields into a single JSON structure 
which it then encrypts in a single operation.   

### @EncryptionKeyId

This is an optional annotation which you can place on a (String) field in your entity and the library will set
it to the ID of the crypto key that was used to perform the
encryption. This is not necessary for decryption purposes (the CryptoKey.key ID is also stored inside the @EncryptedData
anyway) but it is useful for more performant rekey query purposes so it's recommended to have this anyway
as it won't hurt and can be useful later.
It would basically be used to find the records which are (or aren't) using a certain encryption/HMAC key so that they can be
rekeyed with the current encryption key.

# Getting Started
The following instructions detail how to use this library. We use Springboot for our examples but that's an arbitrary
choice, you'll write your application however you want. Mango4j-crypto has very few dependencies and doesn't know what 
you do with your entities after encryption/decryption.
An example entity is as follows:

# Encryption

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



# CryptoKey Provider

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

# CryptoShield Setup
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

# HMAC Strategies

A core concept in the mango4j-crypto library is that of HMAC strategies. There are various ways that an application
could choose to implement key-rotation friendly HMAC functionality (please read the 
[general documentation](/documentation/docs/general/general.md#hmac-key-rotation-challenges) for a detailed
explanation of this material) and this library provides 3 
[HMAC Strategies](/documentation/docs/general/general.md#hmac-strategies) out of the box.

You can choose which ones to apply to your application entities by using the corresponding class level annotation. The
library authors strongly advise application developers to consider
the @ListHmacStrategy unless there are strong reasons not to. Currently, the library supports the following (in
order of preference of the mango4j-crypto team):
<br>
@ListHmacStrategy
<br>
@SingleHmacStrategy
<br>
@DoubleHmacStrategy
<br>

But we'll start with the Single HMAC Strategy as that's the easiest to understand. In this example we also need to 
generate HMACs for both the pan and username fields as they both need to be searchable and username needs to be unique 
in our application.

## Single HMAC Strategy

```java language=java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity(name = "USER_PROFILE")
@SingleHmacStrategy
public class UserProfileEntity {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	@Hmac
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

	@Column(name = "USERNAME_HMAC", unique = true)
	private String userNameHmac;

	@Column(name = "PAN_HMAC")
	private String panHmac;

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

> **NOTES**:
> * We've added the @SingleHmacStrategy annotation to the class.
> * We've added 2 new fields 'panHmac' and 'userNameHmac' to the entity. This is because HMACs need to be stored separately, 
>   and the convention the SingleHmacStrategy uses is that the hmac fields must be named the same as the source fields 
>   with the suffix 'Hmac'. So the 'pan' field gets its HMAC calculated and set into the 'panHmac' field and same for userName.
> * Again, you'll notice that we didn't bother defining getters/setters for the USERNAME_HMAC, PAN_HMAC fields either, 
>   for the same reason that we didn't bother defining getters/setters for the ENCRYPTED_DATA field.
> * The panHmac and userNameHmac fields are persisted to the DB in our example and each have their own columns 
>   (we're using Hibernate here). 
> * The USERNAME_HMAC also has a unique constraint on it.

<br>

## List HMAC Strategy

```java language=java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.ListHmacStrategy;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;
import ie.bitstep.mango.crypto.domain.Unique;
import ie.bitstep.mango.crypto.tokenizers.PanTokenizer;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@ListHmacStrategy
@Document(collection = "UserProfile")
public class UserProfileEntityForListHmacStrategy implements Lookup, Unique {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	@Hmac(purposes = {Hmac.Purposes.LOOKUP, Hmac.Purposes.UNIQUE})
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	private Collection<CryptoShieldHmacHolder> lookups;

	private Collection<CryptoShieldHmacHolder> uniqueValues;

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
	private String id;

	private String favouriteColor;

	@EncryptedData
	private String encryptedData;

	@EncryptionKeyId
	private String encryptionKeyId;

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

	@Override
	public void setLookups(Collection<CryptoShieldHmacHolder> lookups) {
		this.lookups = lookups;
	}

	@Override
	public List<CryptoShieldHmacHolder> getLookups() {
		return lookups;
	}

	@Override
	public void setUniqueValues(Collection<CryptoShieldHmacHolder> uniqueValues) {
		this.uniqueValues = uniqueValues;
	}

	@Override
	public List<CryptoShieldHmacHolder> getUniqueValues() {
		return uniqueValues;
	}

}
```
<br>

The above example entity is designed for MongoDB (as it's the most suitable DB for this HMAC strategy). If you are using
it with an SQL DB check out the [mango4j-crypto-example](https://github.com/bitstep-ie/mango4j-examples/tree/main/mango4j-crypto-example) demo application which does the exact same for an SQL DB.

> **NOTES:**
> * Similar to the SingleHmacStrategy sample entity, the userName field is annotated with @Hmac but here it also has a 
>   'purposes' definition. This can have the values of Purposes.LOOKUP, Purposes.UNIQUE, or both depending on what purpose that field 
>   is being HMACed for. If no value is specified then it defaults to Purposes.LOOKUP.
> * The pan field also has the @Hmac annotation but no purposes definition so it defaults to Purposes.LOOKUP
> * Entities which use @ListHmacStrategy must implement either the Lookup interface, the Unique interface or both. Since this entity uses
    HMACs for both purposes it implements both interfaces. Having to implement these interfaces makes the List HMAC Strategy quite 
>   different from other HMAC designs and that is shown in your entity definition. But it's also what makes it the most powerful strategy.
> * Unlike the other HMAC strategies this one doesn't have associated target HMAC fields with the 'Hmac' suffix. Instead,
    it implements the methods getLookups() and setLookups() from
    the Lookup interface and the getUniqueValues() and setUniqueValues() from the Unique interface. The library calls back
    to these methods to get and set the HMACs. This is what
    makes this the most powerful HMAC strategy, we can have as many HMACS for as many keys or tokenized values as needed.
> * If you are using HMACs for unique constraint purposes, make sure to create the appropriate unique constraint definitions on your
    DB. Generally you would place a compound unique constraint on the columns representing CryptoShieldHmacHolder.alias 
    and CryptoShieldHmacHolder.value (and tenant ID if applicable).

> **Note:** When calling CryptoShield.encrypt() for entities which have been updated (as opposed to newly created),
> make sure that the setLookup() and setUniqueValues() methods _completely replace_ the existing lists! Do not append to
> the existing lists!!!

### HMAC Tokenizers

If using the ListHmacStrategy for an entity you can make use of HMAC Tokenizers by specifying them in the @Hmac
annotation's HmacTokenizers method. Like:

```java language=java

@Hmac(HmacTokenizers = {PanTokenizer.class})
private transient String pan;
```

The library will then generate a series of alternative HMACs for that field using those HmacTokenizer classes. For
example the PanTokenizer (which is included in the library) in
the sample code above will result in the lookup HMAC list for that entity including the HMAC of the last 4 digit of the
PAN, the HMAC of the first 6 digits of the PAN, the HMAC of
the PAN without dashes or spaces (if there are any). These alternative representations will then be stored along with 
the HMAC of the full original PAN that was supplied. The library has some standard HMAC tokenizers, please see the javadocs
for each one to learn what HMAC representations they generate. Applications can supply their own HmacTokenizers with
whatever tokenization logic they need by implementing the
[HmacTokenizer](/mango4j-crypto/src/main/java/ie/bitstep/mango/crypto/tokenizers/HmacTokenizer.java) interface. 
If you have created a HmacTokenizer you think would be generally useful to others please let us
know and we'll add it to the library. Using HMAC Tokenizers
will help applications with more flexible searching functionality and is another reason that the ListHmacFieldStrategy
is the most powerful of the 3 core HMAC strategies.

### Compound Unique Constraints With The List HMAC Strategy
One extra challenge when using the List HMAC strategy is that if you have a requirement of needing to create a compound 
unique constraint on a group of fields that include a HMAC field then this cannot be done the normal way. You can 
create these types of constraints using the 
[@UniqueGroup](/mango4j-crypto/src/main/java/ie/bitstep/mango/crypto/annotations/UniqueGroup.java) 
annotation.  You can place this annotation on each field marked with @Hmac and give them all the same name and a unique 
order number (which you must never change!) and the library will calculate a single unique HMAC for them all.
> NOTE: Mixing HMAC and cleartext fields in a unique group is fine. But at least one field in the group must be marked 
> with @Hmac otherwise the library will throw an error on startup.

## Double HMAC Strategy
Please read the [the official general documentation](/documentation/docs/general/general.md#double-hmac-strategy) for a description 
of the Double HMAC Strategy and for when you might want to use it. The entity definition when using it is similar to the 
one for the Single HMAC Strategy. Below is an example entity definition.

```java language=java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.DoubleHmacStrategy;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@DoubleHmacStrategy
@Entity(name = "USER_PROFILE_ENTITY_FOR_DOUBLE_HMAC_STRATEGY")
public class UserProfileEntity {

    @Encrypt
    @Hmac
    private transient String pan;

    @Encrypt
    @Hmac
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

    @Column(name = "USERNAME_HMAC_1", unique = true)
    private String userNameHmac1;

    @Column(name = "USERNAME_HMAC_2", unique = true)
    private String userNameHmac2;

    @Column(name = "PAN_HMAC_1")
    private String panHmac1;

    @Column(name = "PAN_HMAC_2")
    private String panHmac2;

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

> **NOTES**:
> * We've added the @DoubleHmacStrategy annotation to the class.
> * This entity definition is almost the same as the one for SingleHmacStrategy except that each field annotated with 
>   @Hmac has 2 associated HMAC fields 'panHmac1'/'panHmac2' and 'userNameHmac1'/'userNameHmac2'. This is because 
>   with the Double HMAC Strategy we need 2 HMACs to be stored separately for each HMAC source field. 
> * Again, you'll notice that we didn't bother defining getters/setters for the USERNAME_HMAC_1, USERNAME_HMAC_2, 
>   PAN_HMAC_1 or PAN_HMAC_2 fields either, for the same reasons as mentioned before.
> * The panHmac1, panHmac2, userNameHmac1 and userNameHmac2 fields are persisted to the DB in our example and each have their own columns 
>   (we're using Hibernate here). 
> * The USERNAME_HMAC_1 and USERNAME_HMAC_2 each have a unique constraint on them also.
> * Application search code must look for matching HMACs in both of the HMAC columns associated with each HMAC source 
    field. So those queries become OR queries in the case of multiple HMAC keys in use. You can see the 
>   [mango4j-examples code](https://github.com/bitstep-ie/mango4j-examples/blob/main/mango4j-crypto-example/src/main/java/ie/bitstep/mango/examples/crypto/example/doublehmacstrategy/service/UserProfileService.java#L62) to see an example of what this might look like.

<br>

# Key Rotation
Key rotation is almost fairly straightforward when you just think of it as an additive process. A new encryption or HMAC key is 
added to the system but the old keys are left as they are. Only when no more records are left which were encrypted, or 
has had HMACs calculated, with an older key should that key be removed from the system. As long as your 
CryptoKeyProvider implementation works as prescribed then things should be fine. 
[But make sure you understand how HMACs are different](/documentation/docs/general/general.md#hmac-key-rotation-challenges)...

# Rekeying
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
[general documentation](/documentation/docs/general/general.md#rekeying-re-encrypting-existing-records-with-the-new-key) 
for an explanation of these values. Once the CryptoKey.rekeyMode field is set to either
KEY_ON or KEY_OFF this RekeyScheduler will trigger the rekeying process the next time it runs (defined by
`withRekeyCheckInterval()` as above).

> NOTE: You can still use the RekeyScheduler to configure a rekey for any entity that only has @Encrypt fields (and
> doesn't have HMACs). It's just that HMAC rekey is currently only supported for entities that use the List HMAC Strategy.



# Encryption Service Delegates
Mango4J Crypto uses pluggable Encryption Service Delegates to carry out cryptographic operations at runtime. There are several encryption service delegates currently supported (and more to come). Please see the 
[delegates section](/documentation/docs/delegates) for documentation on each. 

You can also create your own EncryptionServiceDelegate implementations by subclassing the
[EncryptionServiceDelegate](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/EncryptionServiceDelegate.java) class and
implementing the abstract methods with your own logic using your cryptographic provider of choice.