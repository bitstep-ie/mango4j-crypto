# Delegates

In mango4j-crypto all the code for cryptographic operations is hidden behind an abstraction we refer to as the '
Encryption Service Delegate'. What this means is that an infinite number of approaches can be used to
perform the cryptographic operations by allowing developers to supply their own Encryption Service Delegates. Just
create your own subclass of
the [EncryptionServiceDelegate](/mango4j-crypto-core/src/main/java/ie/bitstep/mango/crypto/core/encryption/EncryptionServiceDelegate.java)
class and implement the abstract methods. Coupled with the CryptoKey objects this allows applications to support
multiple
types of cryptographic providers or different cryptographic approaches depending on application requirements. This also
allows applications to support different cryptographic providers at the same time (e.g. different regions using
different providers) without needing to change any application code. And it also allows keys to be rotated from one
provider to another without needing to change any application code (and potentially without even restarting the
application).
<br>
<br>
Mango4j-crypto comes with a few built-in Encryption Service Delegate implementations which you can find documented here, on the left.

