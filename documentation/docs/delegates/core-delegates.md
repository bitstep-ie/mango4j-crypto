# Production Delegates

## PBKDF2 Encryption Service Delegate
The [PBKDF2EncryptionService](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/PBKDF2EncryptionService.java) is a provided EncryptionServiceDelegate implementation that uses the JDKs Java Cryptography Architecture (JCA) for encryption and decryption. This is a real encryption service that could be used for production deployments (make sure to store the pass phrase in a secure manner) and can also be useful for testing purposes. It supports various encryption algorithms, modes and padding schemes that are available in the JDK. You can configure these values by configuring the appropriate attributes in the [CryptoKey](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/domain/CryptoKey.java) configuration map. An example CryptoKey definition for the PBKDF2EncryptionService would be as follows:

```json
{
    "id": "<<some-unique-key-id>>",
    "type" : "PBKDF2",
    "usage" : "ENCRYPTION",
    "configuration" : {
      "keySize": 128,
      "algorithm": "AES",
      "mode": "GCM",
      "padding": "NoPadding",
      "iterations": 10,
      "gmTagLength": 128,
      "passPhrase": "<<my-secure-passphrase>>",
      "ivSize": "12",
      "salt": "16"
  },
  ......other CryptoKey fields
}
```
<br>
<br>

## Wrapped Key Encryption Service Delegate
The [WrappedKeyEncryptionService](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/wrapped/WrappedKeyEncryptionService.java) is a provided EncryptionServiceDelegate implementation that uses the JDKs Java Cryptography Architecture (JCA) for encryption and decryption using a uniquely generated key for each encryption operation. This key is "wrapped" (encrypted) with the wrapping key. This is the same approach that other providers such as the AWS Encryption SDK (they call it envelope encryption) to carry out encryption operations locally but keeping the generated keys secure. So to break it down, it works like this:

Everytime encrypt is called, a new random key is generated for the encryption operation. This key is then encrypted (wrapped) with the wrapping key and stored in the ciphertext along with the encrypted data. When decrypting, the library extracts the wrapped key from the ciphertext, decrypts (unwraps) it with the wrapping key to get the original generated key and then uses that key to decrypt the data. This approach allows you to have a unique key for each encryption operation while still keeping those keys secure with a wrapping key. The configuration for using this encryption service is a bit more complex than the PBKDF2EncryptionService as you need to have both a wrapping CryptoKey and a content CryptoKey configured in your system and you need to specify which one is which in their configurations. Please see the javadocs for the WrappedKeyEncryptionService and the CryptoKey class for more details on how to configure this encryption service.

Here is an example of a Wrapped Crypto Key:
```json

{
"id": "<<some-unique-key-id>>",
"type" : "WRAPPED",
"usage" : "ENCRYPTION",
"configuration" : {
    "kek" : "<<some-unique-key-id-of-the-wrapping-encryption-key>>",
    "ivSize": "12",
    "keySize": 128,
    "algorithm": "AES",
    "mode": "GCM", 
    "padding": "NoPadding",
    "gmTagLength": 128
},
......other CryptoKey fields
}
```

And here is an example of the corresponding Wrapping Crypto Key:
```json

{
"id": "<<some-unique-key-id-of-the-wrapping-encryption-key>>",
"type" : "BASE64",
"usage" : "ENCRYPTION",

  ......other CryptoKey fields
}
```

> **NOTE:** Notice how in the WRAPPED CryptoKey configuration (the first one) we specify the 'kek' attribute which is the ID of the wrapping key (the 2nd one) that should be used for this wrapped key ('kek' stands for Key Encryption Key).

In the example CryptoKey pair above we use the base64 encryption service for the wrapping key just for simplicity of the example, but in a production deployment you would use a real encryption service for the wrapping key such as an implementation of the EncryptionServiceDelegate that uses your cloud provider's Key Management Service (KMS) for encryption operations.
<br>
<br>
<br>
## Cached Wrapped Key Encryption Service Delegate
The [CachedWrappedKeyEncryptionService](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/wrapped/CachedWrappedKeyEncryptionService.java) is a provided EncryptionServiceDelegate implementation that works almost the same way as the WrappedKeyEncryptionService except for that it caches keys in memory for a certain period for much better performance. So it is a compromise between security and performance. The keys are stored in an in-memory vault which uses a secret key generated on application startup to offer slightly better protection of the keys while in the cache. This obviously isn't foolproof, if somebody can do a dump of the heap they could potentially track down the vault key and decrypt the keys in the cache. So this should only be used if you have other controls in place to protect against this type of attack and you should also make sure to set the cache period to the minimum that you can get away with in your application. The configuration for using this encryption service is the same as the WrappedKeyEncryptionService (see previous section for example CryptoKey definition) but you also need to specify the cache period in CachedWrappedKeyEncryptionService using the constructor parameters.

The relevant constructor parameters are:

**entryTTL:** This is the time to live for each key in the cache for decryption purposes. Once a key has been in the cache for this amount of time it will be evicted from the cache (and the key bytes will be destroyed) and the next time it is needed it will be unwrapped again using the WRAPPING key and re-cached. Set this to the minimum amount of time that you can get away with in your application to minimise the risk of keys being compromised while in the cache.
<br>
**currentEntryTTL:** This is the time to live for the current encryption key in the cache. Whereas the WrappedKeyEncryptionService generates a new Data Encryption Key on every encryption operation, the CachedWrappedKeyEncryptionService generates one and stores it in the cache for subsequent encryption operations until it expires. The currentEntryTTL parameter is the length of time that the current encryption key will be stored in the cache before it expires and a new one is generated. Set this to the minimum amount of time that you can get away with in your application to minimise the risk of keys being compromised while in the cache.
<br>
**cacheGracePeriod:** Short period for which expired keys can remain available to allow for clock skew and to avoid situations where a key is obtained from the cache just before expiration and then the key material subsequently destroyed before the actual encryption/decryption is carried out by the delegate. Set this to a short period of time, like a few seconds.

The CachedWrappedKeyEncryptionService is a good option to consider if you want to get the performance benefits of caching for wrapped keys but you also want to have some level of protection for the keys while in the cache. Unlike the WrappedKeyEncryptionService which generates a new Data Encryption Key for every encryption operation and subsequently encrypts that key with the WRAPPING key, the CachedWrappedKeyEncryptionService generates one, encrypts it with the WRAPPING key and stores it in the cache for subsequent encryption operations until it expires. So it can dramatically cut down on calls to the WRAPPING key service for encryption operations.
<br>
Likewise, for decryption operations, if the key needed for decryption is in the cache it can be used directly without needing to call the WRAPPING key service to unwrap it first. So this can also cut down on calls to the WRAPPING key service for decryption operations as well.
