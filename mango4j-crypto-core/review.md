# Code and security review

Static review of all production Java classes and the module POM, with each finding checked against the code. Findings marked *reproduced* were also demonstrated by running the code. Dependencies were not scanned for known vulnerabilities.

**Quality gates:** mutation 99% (165/167), line coverage 99%; PIT thresholds are set to 98/99.

## Findings

1. **Decryption takes its cipher parameters from the stored ciphertext** (High). `PBKDF2EncryptionService.decrypt` builds the cipher from the algorithm, mode and padding in the container (`:162`) and the key size, iteration count and GCM tag length from it (`:151`); `CachedWrappedKeyEncryptionService.decrypt` and `WrappedKeyEncryptionService.decrypt` do the same through `CipherConfig.of(EncryptedDataConfig)`. Anyone who can write stored ciphertext can change a GCM record to `CBC`, which has no authentication, and the library will decrypt it. Take mode, algorithm, padding and tag length from the trusted `CryptoKey` configuration and reject a container that disagrees.

2. **CBC is accepted for encryption and carries no authentication** (High). `CipherManager.java:42` supports `CBC`, and the PBKDF2 and wrapped-key services (`PBKDF2EncryptionService.encrypt`, `WrappedKeyEncryptionService.encrypt`) store only IV and ciphertext with no MAC. Altered ciphertext can decrypt to altered plaintext, and padding errors can form a padding oracle if the caller exposes the outcome. Restrict new encryption to an authenticated mode and plan a migration for existing CBC data.

3. **The ciphertext controls the PBKDF2 work factor** (Medium). `PBKDF2EncryptionService.java:151-157` reads `iterations` and `keySize` from the container and passes them straight to PBKDF2 before anything is authenticated. A very large iteration count in a stored or submitted container ties up CPU. Bound the values against the trusted key configuration before deriving.

4. **The current data key is shared across key configurations** (Medium). `CachedWrappedKeyEncryptionService.java:58` uses one static cache, and `getCurrentWrappedKeyHolder` (`:191`) returns its current holder without looking at the supplied key configuration. Encrypting under a second wrapping key or key size can reuse a data key wrapped under the first (and of the first's size). Key the current holder by the configuration.

5. **`InMemoryKeyVault` does not protect keys from a memory dump** (Medium). `InMemoryKeyVault.java:67` stores the AES vault key in the same `VaultEntry` as the IV and the ciphertext it protects, so anyone who can read the heap can decrypt every stored key. It hides keys from casual inspection only; document it that way, or hold the vault key outside the process. (`get` also throws a bare `RuntimeException` at `:88` instead of the module's crypto exception.)

6. **HMAC computation re-derives the PBKDF2 key for every holder** (Medium). `PBKDF2EncryptionService.java:189` derives the key inside the per-holder loop with the full iteration count, although passphrase, salt and iterations are the same for a given key. An entity with many HMAC fields multiplies the cost. Derive once per key and reuse it.

7. **A global lock is held across remote key operations** (Medium). `CachedWrappedKeyEncryptionService.getCurrentWrappedKeyHolder` (`:191`) and `getWrappedKeyHolder` (`:285`) synchronise on the static cache while calling `encryptionService.encrypt/decrypt`, which for a KMS-backed wrapping key is a network call. Every thread that needs a data key waits behind a slow unwrap. Use per-key loading or a lock-free cache.

8. **Insecure algorithms and test delegates are available to production configuration** (Medium). `Algorithm.java:21` offers `DES` and `DESede`, `EncryptionService.java:60` registers every delegate it is given with `put` (a duplicate key type silently replaces the earlier delegate), and `IdentityEncryptionService` and `Base64EncryptionService` are in the main source set and perform no encryption. A mistaken registration or configuration weakens protection with no warning. Remove the test delegates from the shipped artifact, reject duplicates, and drop the weak algorithms.

9. **Key bytes are not wiped on error paths** (Low). `CachedWrappedKeyEncryptionService.java:141,271` zero the copied key only after a successful cipher operation, and the cache-miss decrypt path (`:295`) never zeroes `decodedKey` after the holder copies it into the vault. `PBEKeySpec` and the derived bytes in `PBKDF2EncryptionService.java:285` are never cleared. Wipe in `finally`.

10. **Static state is created and reconfigured at class-load and construction time** (Low). `CachedWrappedKeyEncryptionService.java:64` creates a non-daemon `ScheduledExecutorService` that is never shut down (it can keep the JVM alive and pin the class loader), and each constructor (`:89`) overwrites the TTLs of the one shared cache for all instances.

11. **Malformed ciphertext does not always produce the formatter exception** (Low). `CiphertextFormatter.java:41` dereferences `jsonNode.get("cryptoKeyId")` without a null check and catches only `JacksonException`, so a missing member or a null root escapes as `NullPointerException`.

12. **Replacing a keyed entry never closes the old value** (Medium). `LingeringCloseCache.java:180` calls `cache.put(...)` and discards the previous entry, so it is never moved to the evicted set. An `AutoCloseable` value (for example a cached encryption key holder) that is replaced by `put` is not closed by the cache, not even by `shutdown()`, and the key material stays in memory until garbage collection. Move the replaced entry to delayed eviction (`put` returns the old value from the map) and test replacement and shutdown.

13. **`putCurrent` can lose cleanup under concurrent writers** (Medium). `LingeringCloseCache.java:220-222` evicts the current entry and then sets the new one as two separate steps. Two concurrent callers can both evict (one gets the old entry, the other `null`) and then both set, so the first caller's new entry is overwritten without being scheduled for cleanup. Swap atomically with `getAndSet` and evict the returned value.

14. **Expiry can evict a newly installed current entry** (Medium). `LingeringCloseCache.java:304` checks that the current entry has expired and then calls `evictCurrentKey()`, which removes whichever entry is current at that moment. If `putCurrent` runs between the check and the removal, the fresh entry is evicted and closed after the grace period while callers still expect it. Remove only the entry that was checked, with compare-and-set.

15. **`clear()` can drop entries added concurrently without closing them** (Low). `LingeringCloseCache.java:403-404` snapshots the map and then clears it in a separate step. An entry inserted in between is removed without being scheduled for cleanup.

16. **Runtime TTL changes are not safely published** (Low). `LingeringCloseCache.java:72-74` declare the TTL and grace-period fields as plain mutable fields, with public setters that run on a different thread from the cache and scheduler methods. Without `volatile` (or equivalent) another thread need not observe an update, which the class documents as supported runtime tuning.

## Notes

- All randomness (IVs, data keys, vault IVs) comes from a `SecureRandom`; there is no use of `java.util.Random`, MD5, SHA-1 or ECB, and HMAC uses HmacSHA256.
- `LingeringCloseCache` has no size bound, and a grace period does not guarantee a value stays open for an arbitrarily long operation; callers must account for both.
- The passphrase is held as a `String` in the key configuration and cannot be wiped.
- Security properties also depend on caller configuration and on the external key providers.
