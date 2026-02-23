# Testing Delegates


## Base64 Encryption Service Delegate
The [Base64EncryptionService](./mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/test/Base64EncryptionService.java) is a provided EncryptionServiceDelegate implementation that simply Base64 encodes the 
plaintext and decodes the Base64 string back to plaintext for decryption. This should only be used for testing purposes 
and should never be made available in a production deployment.
There is no keyConfiguration required for Base64EncryptionService.
<br>
<br>

## Identity Encryption Service Delegate
The [IdentityEncryptionService](./mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/impl/test/IdentityEncryptionService.java) is a provided EncryptionServiceDelegate implementation that basically does nothing. 
It simply stores the plaintext as is and returns the same plaintext for decryption. This should only be used for testing 
purposes and should never be made available in a production deployment. 
There is no keyConfiguration required for Base64EncryptionService.
<br>
<br>
<br>



