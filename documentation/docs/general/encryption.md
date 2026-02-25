# Encryption Service Delegates

In mango4j-crypto all the code for cryptographic operations is hidden behind an abstraction we refer to as the '
Encryption Service Delegate'. What this means is that an infinite number of approaches can be used to
perform the cryptographic operations by allowing developers to supply their own Encryption Service Delegates. Just
create your own subclass of
the [EncryptionServiceDelegate](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/EncryptionServiceDelegate.java)
class and implement the abstract methods. Coupled with the CryptoKey objects this allows applications to support
multiple
types of cryptographic providers or different cryptographic approaches depending on application requirements. This also
allows applications to support different cryptographic providers at the same time (e.g. different regions using
different providers) without needing to change any application code. And it also allows keys to be rotated from one
provider to another without needing to change any application code (and potentially without even restarting the
application).
<br>
<br>
Mango4j-crypto comes with a few built-in Encryption Service Delegate implementations:
<br>

* Production: Wrapped Delegate, Cache Wrapped Delegate
* Test: Base64 Delegate, Identity Delegate

And developers can create their own Encryption Service Delegate implementations to suit their needs. If you do create
your own Encryption Service Delegates which you think would be universally useful then please consider giving back by
making it publicly available, or even submitting a PR to the mango4j-crypto project so that others can benefit from it
too.

# Key objects

CryptoKey objects tell the library which Encryption Service Delegate to use to carry out the actual cryptographic
operations under the hood.
We often see applications representing their encryption/HMAC keys in their code with simple Strings (representing an AWS
KMS key ID or key ARN for example) rather than key objects, but representing your key information with objects instead
provides much more flexibility with how your encryption works. For example, this library represents keys in the code
with the following object:

```java
public class CryptoKey {
	private String id;
	private CryptoKeyUsage usage;
	private String type;
	private Map<String, Object> configuration;
	private Instant keyStartTime;
	private RekeyMode rekeyMode;
	private Instant createdDate;
	private Instant lastModifiedDate;
}
```

*id:* Just a plain old random GUID

*usage:* What this key will be used for (either encryption or HMAC)

*type:* The type of the Encryption Service Delegate that this key will use to carry out its cryptographic operations.
This must match the value returned from the
desired [EncryptionServiceDelegate.supportedCryptoKeyType()](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/EncryptionServiceDelegate.java#L17)
implementation.
<br>
For example: The
included [CacheWrappedKeyEncryptionService.supportedCryptoKeyType()](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/wrapped/CachedWrappedKeyEncryptionService.java#251)
returns the value "CACHED_WRAPPED", so if you wanted to use that Encryption Service Delegate implementation then you
would have a CryptoKey object with this 'type' field set to "CACHED_WRAPPED". At runtime the library matches the
CryptoKeys with their corresponding EncryptionServiceDelegates by comparing this 'type' field. If you create you own
Encryption Service Delegate implementation, you can define this field however you like.

*Configuration:* This field stores the information about the key that the Encryption Service Delegates use to carry out
their operations. It would never contain the actual
bytes of the key or related confidential information (at least not in the clear). Instead, it would usually contain a
reference to the key. For example: if the 'type' of this key was AWS_KMS then this map would have an entry called "
keyArn" with the value of the AWS Key ID or Key ARN. Each Encryption Service Delegate implementation will know what
configuration information it needs to carry out its operations so the application just needs to make sure that the right
information is present in this map for the given key type.

*keyStartTime:* Optional field which is only used for HMAC CryptoKeys. When used this can alleviate some of the shortcomings with the [Single HMAC Strategy](#single-hmac-strategy) that are described further in this document. If you are using this field it should be set when the CryptoKey is created in your application. It's very important to set this to some time in the future which is greater than the key cache time. i.e. by the time this ketStartTime date passes, all application instances should know about this key.

<br>
<br>
A big advantage of using CryptoKey objects to represent cryptographic key information is that it allows applications to easily support multiple cryptographic providers while keeping code clean and encryption code
abstracted. It could also allow you to rotate from one type of key to another (e.g. AWS_KMS to AZURE_DEDICATED_HSM) with no application code changes. Or you could support different
encryption delegates in different regions without having to write any custom application code to support that.

# Ciphertext representation

When [CryptoShield.encrypt()](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto/src/main/java/ie/bitstep/mango/crypto/CryptoShield.java#L202)
is called on an object the library will set
the [@EncryptedData](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto/src/main/java/ie/bitstep/mango/crypto/annotations/EncryptedData.java)
field in the object to the calculated ciphertext.
This final ciphertext is represented in a standardised way for encryption (not HMACs). Instead of just returning the
straight
ciphertext output it will return it as a JSON String with the following definition:

```json
{
  "cryptoKeyId": "someKeyId",
  "iv": "someInitializationVector",
  "data": {}
}
```

where:

- *cryptoKeyId* is the identifier of the crypto key object (e.g. the CryptoKey.id field) in your system that was used to
  carry out the cryptographic operation
- *iv* is the [Initialization Vector](#Whats-an-IV) that was used for the cryptographic operation
- *data* is the actual output that was returned from the Encryption Service Delegate's encrypt() method, the ciphertext
  will be included here.
  Each delegate may return different data here depending on the cryptographic provider or method that it uses, or what
  information it
  defines as necessary to include. This is why it's a map, because it needs to be flexible enough to accommodate
  different ciphertext data structures that different EncryptionServiceDelegates define.
