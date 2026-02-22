# Encryption Service Delegates
Mango4j-crypto comes with some provided EncryptionServiceDelegate implementations, 2 of which should only be used for 
testing purposes and should never be made available in a production deployment. These are the Base64EncryptionService and
the IdentityEncryptionService. The Base64EncryptionService simply Base64 encodes the plaintext and the IdentityEncryptionService returns the plaintext as the ciphertext. The library also comes with a JCEEncryptionService which is a real encryption service that uses the Java Cryptography Extension (JCE) and should be used for production deployments. You can also create your own EncryptionServiceDelegate implementations if you need to by subclassing the
[EncryptionServiceDelegate](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/EncryptionServiceDelegate.java) class and
implementing the encrypt and decrypt methods with your own logic using your cryptographic provider of choice.