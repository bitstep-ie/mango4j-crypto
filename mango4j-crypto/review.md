# Code and security review

Static review of all production Java classes and the module POM, with each finding checked against the code. Findings marked *reproduced* were also demonstrated by running the code. Dependencies were not scanned for known vulnerabilities. The key-rotation scheduler describes itself as experimental.

**Quality gates:** mutation 99% (421/424), line coverage 100%; the mutation threshold is set to 99.

## Findings

1. **Key rotation skips exactly the entities that have encrypted fields** (High). `RekeyScheduler.java:123` continues when `getFieldsToEncrypt(...)` is **not** empty, while the log line beside it says the entity has no encrypted fields. A KEY_ON re-encrypt therefore ignores encrypted entity types and builds tasks only for types without any. If other tasks are created, older keys can then be marked for deletion while records of the skipped type still depend on them. Invert the condition.

2. **Older keys are retired even when rotation was interrupted or records failed** (High). `reHmac` (`:222`) and the re-encrypt path (`:176,184`) call `removeKey`/`markKeyForDeletion` after `rekey(...)` returns, without checking the outcome. `rekey` returns a count after an interrupt (`:382` returns only from the lambda) and failed records are only counted in `ProgressTracker`, whose default `maximumToleratedFailuresPerExecution` is `-1` (`RekeySchedulerConfig.java:25`), which means unlimited. Do not retire a key unless every task finished and a verification query finds no remaining records.

3. **Failed records are saved with the rest of the batch** (Medium). `RekeyScheduler.java:421` saves the whole original batch after `rekeyEntity` has caught per-record decrypt/encrypt failures. A failed entity can be partly decrypted or partly re-encrypted when it is persisted. Save only the successful records.

4. **Compound uniqueness HMAC inputs are ambiguous** (Medium). `ListHmacFieldStrategy.java:376` appends the group's field values with no delimiter or length. `("ab","c")` and `("a","bc")` produce the same input, giving false uniqueness conflicts, and a null member appends the text `null`, colliding with a real `"null"`. Use an unambiguous, versioned encoding.

5. **Setting a source field to null leaves its old HMAC** (Medium). `SingleHmacFieldStrategy.java:117` and `DoubleHmacFieldStrategy.java:162` skip a null source field without clearing the persisted HMAC fields. An updated record stays searchable by its old value or keeps occupying a unique index.

6. **Clearing every encrypted field keeps the old ciphertext** (Medium). `CryptoShield.java:430` writes the ciphertext field only when the JSON object is non-empty. If all confidential fields are set to null and re-encrypted, the previous ciphertext is retained and a later decrypt restores the old values.

7. **Rekey strategy detection is reversed** (Medium). `RekeyCryptoShield.java:31` tests `actualClass.isAssignableFrom(ListHmacFieldStrategy.class)`, which is true only when the actual class is the list strategy or one of its supertypes. A subclass of `ListHmacFieldStrategy` (and likewise of the double strategy at the next branch) is not wrapped with the rekey-specific version and uses normal key selection during rotation. Use `instanceof`.

8. **Duplicate group orders silently drop a field from the HMAC** (Medium). `UniqueGroup.java:13` stores members in a `TreeSet` ordered only by `order`, so two members with the same order compare equal and one is dropped (while `allUniqueGroupFields` still lists both, so validation does not notice). The uniqueness HMAC then omits a configured field.

9. **Repeatable group annotations are only partly supported** (Low). `UniqueGroupSet` reads repeatable annotations with `getAnnotationsByType`, but `UniqueGroup.java:22` uses `getAnnotation`, which returns `null` when a field carries more than one `@UniqueGroup`, so registration fails with "no associated annotation".

10. **List HMAC rekey assumes every entity implements `Lookup`** (Low). `RekeyListHmacFieldStrategy.java:44` casts the entity to `Lookup` unconditionally, so an entity with only unique-purpose fields (implementing `Unique` only) throws `ClassCastException`.

11. **The older-key validation skips the oldest key** (Low). `RekeyScheduler.java:236` uses `subList(1, size - 1)`, which excludes the last (oldest) element; with two keys it checks nothing. A misconfigured oldest KEY_ON key passes.

12. **Cyclic cascade types overflow the stack at registration** (Low). `AnnotatedEntityManager.java:112` recursively registers cascaded field types with no visited set, so a self-referencing or mutually referencing `@CascadeEncrypt` model throws `StackOverflowError` during initialisation.

13. **Registered field metadata is exposed mutably** (Low). `AnnotatedEntityManager.java:315` (and the two similar getters) return the internal lists, so a caller can remove a field from the shared registration and later encryption silently omits it.

14. **The retry wrapper does not cancel interrupted work, and failed encryption is not rolled back** (Low). `CryptoShield.java:263` waits on the scheduled future and, when interrupted, throws without cancelling it, so the task may still run later against an entity the caller has moved on from. `:207` (`encryptAndSerialize`) mutates HMAC, ciphertext and key-id fields before serialisation with no rollback if encryption or serialisation fails, and a failure in a cascaded entity leaves earlier entities already changed.

## Notes

- No sensitive values (plaintext, passphrases, ciphertext) are written to logs in this module.
- The `keyrotation` package is excluded from mutation testing, so none of the rotation findings above is covered by it.
