# Code and security review

Static review of both production classes, the POM and the delegate tests. No live AWS call was made. Dependencies were not scanned for known vulnerabilities.

**Quality gates:** mutation and line coverage 100%.

## Findings

1. **Decryption does not bind the ciphertext to the configured KMS key** (Medium). `AwsKmsEncryptionServiceDelegate.java:60` builds a `DecryptRequest` from the ciphertext blob only. The stored key id and the container's `CryptoKey` are ignored, and the response key id is not compared. If the application's principal can decrypt under several KMS keys, a ciphertext produced under another key is accepted. Pass `keyId` so KMS enforces the key, and compare the response.

2. **Asymmetric keys cannot round-trip** (Medium). Encryption sends the configured algorithm (`:50`), but the decrypt request omits both the key id and the encryption algorithm, which KMS requires for asymmetric keys, so asymmetric ciphertext cannot be decrypted by this delegate. The existing mocked decrypt test expects both to be null, so it does not exercise this.

3. **KMS errors are not translated, so the retry logic never retries them** (Medium). The delegate lets `KmsException` (and throttling errors) escape. `CryptoShield.retryableCommand` retries only `TransientCryptoException` and wraps anything else as non-transient, so a throttled or temporarily failing KMS call fails immediately.

## Notes

- KMS encryption context is not supported by the delegate interface; applications that need context-bound ciphertext must account for that.
- `hmac` makes one `GenerateMac` call per holder, sequentially.
