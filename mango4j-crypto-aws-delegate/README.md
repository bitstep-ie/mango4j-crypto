# AWS KMS Encryption Service Delegate

This delegate allows applications to use the Amazon Web Services Key Management Service for cryptographic operations. 
It does this by providing a simple wrapped around the AWS KMS SDK.


The key type for this delegate is "AWS_KMS", so associated CryptoKeys must have their 
[type](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/domain/CryptoKey.java#L43) set to that value.

The following are the fields that must be included in your Cryptokey [configuration](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/domain/CryptoKey.java#L62) 

```JSON
{
  "awsKeyId": "<<Your AWS KMS key ARN/key Identifier>>",
  "algorithm" : "<<AWS KMS ALGORITHM>>"
}
```
<br>
Supported algorithms for encryption/decryption currently are: SYMMETRIC_DEFAULT
<br>
Supported algorithms for HMAC generation currently are: HMAC_SHA_224, HMAC_SHA_256, HMAC_SHA_384, HMAC_SHA_512,   



> Note: Amazon also provide an AWS Encryption SDK which integrates with AWS KMS to provide client side cryptographic 
  operations. This client side approach includes creating Data Encryption Keys for each encryption operation and 
  wrapping them with the AWS KMS master key. Since mango4j-crypto already has support for wrapped encryption we 
  currently do not provide any delegate support for the AWS Encryption SDK. If you want to use the data encryption 
  envelope approach you can just use the 
  [Wrapped Key Encryption Service Delegate](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-wrapped-delegate/src/main/java/ie/bitstep/mango/crypto/core/impl/service/encryption/WrappedKeyEncryptionService.java) 
  with an AWS_KMS (this delegate) CryptoKey as the wrapping key. 
  For performance critical functionality you can also check out using the 
  [Cache Wrapped Key Encryption Service Delegate](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-wrapped-delegate/src/main/java/ie/bitstep/mango/crypto/core/impl/service/encryption/CachedWrappedKeyEncryptionService.java)
  with an AWS_KMS (this delegate) CryptoKey as the wrapping key