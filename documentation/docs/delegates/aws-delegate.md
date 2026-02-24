# AWS Encryption Service Delegate


This delegate allows applications to use the [Amazon Web Services Key Management Service](https://aws.amazon.com/kms/) 
for cryptographic operations. It does this by providing a simple wrapper around the 
[AWS KMS SDK](https://docs.aws.amazon.com/kms/).

> **NOTE**: AWS KMS has a message limit of 4kb so it is not suitable for encrypting larger payloads. 
  See [note about limitations below](#aws-kms-limitations)

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


# AWS KMS Limitations
For applications which need to encrypt payloads larger than 4k and also want more control over how cryptographic operations 
are carried out, Amazon also provide an 
[AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html) which 
integrates with AWS KMS to provide client side cryptographic 
operations. This client side approach includes creating Data Encryption Keys for each encryption operation and 
_wrapping_ (encrypting) them with the AWS KMS master key. Since mango4j-crypto already has support for wrapped key 
encryption we currently do not provide any delegate support for the AWS Encryption SDK. If you want to use the envelope 
approach you can just use the 
[Wrapped Key Encryption Service Delegate](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/wrapped/WrappedKeyEncryptionService.java) 
with an AWS_KMS (this delegate) CryptoKey as the wrapping key. 
For performance critical functionality you can also check out the 
[Cache Wrapped Key Encryption Service Delegate](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/wrapped/CachedWrappedKeyEncryptionService.java) 
with an AWS_KMS (this delegate) CryptoKey as the wrapping key

# How to Use
Add the following dependency to your pom

```xml
<dependency>
    <groupId>ie.bitstep.mango</groupId>
    <artifactId>mango4j-crypto-aws-delegate</artifactId>
    <version>1.0.0</version>
</dependency>
```

Then just create an instance of 
[AwsEncryptionServiceDelegate](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto-aws-delegate/src/main/java/ie/bitstep/mango/crypto/delegates/aws/impl/service/encryption/AwsEncryptionServiceDelegate.java) 
with a configured KmsClient and add it to the list of delegates you configure with your CryptoShield.
For example a Spring configuration might look like this:

```java
@Configuration
public class Config {
	
    @Value("${aws.access.key.id}")
    public String accessKeyId;

    @Value("${aws.secret.access.key}")
    public String secretAccessKey;

    @Value("${aws.region}")
    public String awsRegion;

    @Bean
    public AwsEncryptionServiceDelegate awsEncryptionServiceDelegate() {
        return new AwsEncryptionServiceDelegate(KmsClient.builder()
            .region(Region.of(awsRegion))
            .credentialsProvider(EnvironmentVariableCredentialsProvider.create())
            .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.builder()
            .accessKeyId(accessKeyId)
            .secretAccessKey(secretAccessKey)
            .build()))
        .build());
    }

    @Bean
    public CryptoShield cryptoShield(CryptoKeyProvider cryptoKeyProvider,
                                 List<EncryptionServiceDelegate> encryptionServiceDelegates) {
        return new CryptoShield.Builder()
            .withAnnotatedEntities(List.of(MyConfidentialEntity.class))
	        .withCryptoKeyProvider(cryptoKeyProvider)
            .withEncryptionServiceDelegates(encryptionServiceDelegates)
            .withObjectMapperFactory(new ConfigurableObjectMapperFactory())
            .build();
    }
}
```
<br>

### mango4j-crypto-example
See the [mango4j-crypto-example](https://github.com/bitstep-ie/mango4j-examples/tree/main/mango4j-crypto-example) for 
a working example of using this delegate. 
<br>
Just add the **aws-kms-encryption** profile in the active 
Spring profiles section of the application.yml file. Then pass in your values for the 
_aws.access.key.id_, _aws.secret.access.key_ and _aws.region_ properties.