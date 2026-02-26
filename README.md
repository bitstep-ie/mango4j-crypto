# Mango4j Crypto

[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=bitstep-ie_mango4j-crypto&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=bitstep-ie_mango4j-crypto)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=bitstep-ie_mango4j-crypto&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=bitstep-ie_mango4j-crypto)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bitstep-ie_mango4j-crypto&metric=coverage)](https://sonarcloud.io/summary/new_code?id=bitstep-ie_mango4j-crypto)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=bitstep-ie_mango4j-crypto&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=bitstep-ie_mango4j-crypto)


[![CI](https://github.com/bitstep-ie/mango4j-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/bitstep-ie/mango4j-crypto/actions/workflows/ci.yml)
[![CodeQL](https://github.com/bitstep-ie/mango4j-crypto/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitstep-ie/mango4j-crypto/actions/workflows/codeql.yml)
[![Dependabot](https://github.com/bitstep-ie/mango4j-crypto/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/bitstep-ie/mango4j-crypto/actions/workflows/dependabot/dependabot-updates)


<br />
<div align="center">
    <a href="https://github.com/bitstep-ie/mango4j-crypto">
    <picture>
        <source srcset="documentation/docs/assets/mango-with-text-black.png" media="(prefers-color-scheme: light)">
        <source srcset="documentation/docs/assets/mango-with-text-white.png" media="(prefers-color-scheme: dark)">
        <img src="documentation/docs/assets/mango-with-text-black.png" alt="mango Logo">
    </picture>
    </a>
    <h3 align="center">mango4j-crypto</h3>
    <p align="center">
        A framework for implementing Application Level Encryption in java applications.
        <br />
        <a href="https://bitstep-ie.github.io/mango4j-crypto/latest" target="_blank"><strong>📚 Explore the Official Guide »</strong></a>
        <br />
        <br />
        <a href="https://github.com/bitstep-ie/mango4j-examples" target="_blank">🔎 View Example Application</a>
        &middot;
        <a href="https://github.com/bitstep-ie/mango4j-crypto/issues/new?template=bug_report.md" target="_blank">
            🐛 Report Bug
        </a>
        &middot;
        <a href="https://github.com/bitstep-ie/mango4j-crypto/issues/new?template=feature_request.md" target="_blank">
            💡 Request Feature
        </a>
    </p>
</div>
<br />



# Introduction

Mango4j-crypto is a framework which aims to simplify the implementation of Application Level Encryption (focussing on
data at rest) in Java applications, and ensure that applications follow a flexible and powerful design that can handle
the many tricky scenarios that can occur when implementing the same. It's based on using simple annotations to mark
fields on your entity which the library will then generate the appropriate ciphertext for (encrypted text, HMACs or
both). 
This library is not an encryption provider or standard, it's a framework. Just like Springboot isn't a web 
application, Mango4j-crypto isn't encryption. Mango4j-crypto enables you to implement Application Level Encryption in 
your applications quickly and effectively, just like Springboot enables you to build a web application quickly 
and effectively. It allows you to use any cryptographic approaches you need and doesn't tie you into any particular 
cryptographic provider. This will make more sense after you read [the official general documentation](https://bitstep-ie.github.io/mango4j-crypto/latest/general/general/), so 
please read that to get up to speed. The library has extensive javadocs also, so it's encouraged for developers to read 
those.

The following is a basic quick start guide to getting started with the library. For more complete instructions please read [the 
official guide](https://bitstep-ie.github.io/mango4j-crypto/latest/guide/guide) instead.

You can also check out the mango4j-crypto-example demo module in the 
[mango4j-examples](https://github.com/bitstep-ie/mango4j-examples) repository for a
working Springboot application which shows how to use this library with each HMAC strategy (explained further in this
document).

## Annotations

The main annotations that developers will use are @Encrypt, @Hmac, @EncryptedData, @EncryptionKeyId, @HmacKeyId. 

# Getting Started

Add the following dependency to your pom

```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto</artifactId>
    <version>1.0.0</version>
</dependency>
```

Add the appropriate annotations to your entity definition, for example:
```java
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

Create your implementation of the [CryptoKeyProvider](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/providers/CryptoKeyProvider.java) 
interface. If you store your CryptoKey objects in a database it might look something like this:

```java
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


Create an instance (bean) for CryptoShield in your application config, passing in a list of all your application
  entities which use @Encrypt or @Hmac, for example:

```java

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


Then your application code can encrypt your entities by calling:

```java
        cryptoShield.encrypt(userProfile);
```
And this will encrypt all the confidential fields in your entity and set the resulting ciphertext into the field marked 
with @EncryptedData. 
> **NOTE:** This encrypt operation doesn't affect the original values of the transient fields, they remain exactly as they 
> were (unencrypted). So you can continue working with them in your code after calling CryptoShield.encrypt(). 

<br>
Likewise, to decrypt an entity you can call:

```java
        cryptoShield.decrypt(userProfile);
```

And this will decrypt and reset all the confidential (transient) fields in your entity back to their original values.

Please see [the official guide](https://bitstep-ie.github.io/mango4j-crypto/latest/guide/guide) for a more indepth explanation of all supported features. 