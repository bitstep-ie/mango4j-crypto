# Double HMAC strategy

The Double HMAC strategy is a compromise between the List HMAC strategy and the Single HMAC Strategy that allows for a 
more normal entity design.

This strategy trades the generality of the List HMAC strategy to a more simple relational design and has an added
downside of only allowing 2 HMAC keys to be in use for write
operations at any time. So there will be some applications which this strategy won't suit, particularly those that need
to have 3 or more HMAC keys active for write operations at
any time. Applications which use HMACs for unique value enforcement for long-lived data and only support passive key
rotation (no re-keying) cannot use this strategy. For
applications which require unique value enforcement, using this strategy will mean that you must support re-keying old
data because if you need to introduce a new HMAC key (once
you already have 2 HMAC keys) then you're forced to re-key any HMACs that were calculated with the oldest HMAC key (1rst
HMAC key) onto the most recent HMAC key (2nd HMAC key)
before you can introduce the new (3rd HMAC key)....and so on.

The way the strategy works is the following. You just have the USER_PROFILE table, but it looks like this:

| ID                                   | TENANT_ID  | CIPHER_TEXT                                                          | SOME_OTHER_NON_CONFIDENTIAL_ATTRIBUTE | USERNAME_HMAC_1              | USERNAME_HMAC_2              | ENCRYPTION_KEY_ID                    | HMAC_KEY_ID_1                        | HMAC_KEY_ID_2                        |
|--------------------------------------|------------|----------------------------------------------------------------------|---------------------------------------|------------------------------|------------------------------|--------------------------------------|--------------------------------------|--------------------------------------|
| 9c7e275e-3729-421c-a7c5-cf02bba17f2d | MyTenantID | QmFzZTY0RW5jb2RpbmdPZlVzZXJQcm9maWxlQ29uZmlkZW50aWFsQXR0cmlidXRlcw== | some value In the clear               | QmFzZTY0VmFsdWVPZlVzZXJuYW1l | QmFzZTY0VmFsdWVPZlVzZXJuYW1l | 23a0a1b4-3897-4eaa-b8fa-1818a9540f0c | 31ae30a7-4228-40a9-9078-d5e994491981 | 31ae30a7-4228-40a9-9078-d5e994491981 |

Notice that there are 2 separate columns for the username HMAC.
With this strategy, your application will assume that there could be up to 2 write keys (max) in use at any time so that
it can be prepared to insert 2 HMACs for the username for
each write operation. With the HMAC generated with the old key inserted into the USERNAME_HMAC_1 column and the HMAC
generated with the new key inserted into the USERNAME_HMAC_2
column. If there is only a single key in use then it should insert the same username HMAC twice into both the
USERNAME_HMAC_1 and USERNAME_HMAC_2 columns so that they match.
This keeps the entity design simple and for relational DBs it eliminates the need for multiple tables per entity as is
necessary for the List HMAC strategy. It's important to note
that all search code must search for the HMAC in both columns at all times though, as it could be in either one. This
leads to messier search code.

## Process for re-keying data with the Double HMAC Strategy

1. Add your new HMAC key to the tenant's list of HMAC keys
2. Wait until the HMAC key cache expiry time has passed (if applicable), so that all application instances are using the
   new HMAC key.
3. Kick off the re-keying job.
4. The re-keying job should find each record it needs to re-key. This depends on application requirements but will
   probably fall into one of 2 criteria:
   a. Any record which doesn't yet have HMACs calculated with the new HMAC key - **common for full re-keying of all data
   **
   b. Any record which has HMACs calculated with some old HMAC key (that you're trying to remove from the system), but
   does not have HMACs calculated with the new HMAC key -
   **common for passive key rotation where no unique constraint support is required**
5. For each record found, decrypt the record, calculate the HMAC(s) with the new key, overwrite the X_HMAC_2 columns (
   e.g. the USERNAME_HMAC_2 column above) with the new HMAC(s).
   X_HMAC_1 columns (e.g. the USERNAME_HMAC_1 column above) values should remain as they are, untouched.
6. Wait for all applicable records to be re-keyed
7. Remove the old HMAC key from the tenant's list of HMAC keys
8. Wait until the HMAC key cache expiry time has passed (if applicable), so that all application instances are no longer
   using the old HMAC key.
9. Copy X_HMAC_2 column values into X_HMAC_1 columns for all fields in all records, something like:

```sql
UPDATE table
SET USERNAME_HMAC_1 = USERNAME_HMAC_2
```

**Pros of the Double HMAC strategy:**

- Fairly solid HMAC design which will probably work for a good number of application requirements
- Relational DB friendly, single table design
- Negligible performance impact. Only calculates and inserts a max of 2 HMACs (per attribute) for each write operation
- Supports zero-outage search
- Supports unique constraint integrity
- Supports both the previous points for applications which cache HMAC keys

**Cons of the Double HMAC strategy:**

- For applications which use HMACs for unique value enforcement and only support passive key rotation (don't re-key
  data), it potentially only supports ones with relatively short
  data retention
- For applications which use HMACs for unique constraint support and have long-lived data, this strategy requires
  re-keying all data (by some background task) once a new HMAC key
  is introduced. Once this task finishes the old key can be removed
- Introduces a small window for mistakes to be made during HMAC key rotation. A code defect could mix up the HMAC
  columns which would cause issues. Or if the order of the HMAC keys
  in the list of HMAC keys is wrong then this could cause serious problems
- Application search code looks awkward as searches have to look in both HMAC columns (OR query)
- Supporting HMAC tokenization would be very clunky

<!--name=admonition;type=info;title=Note;body=You don't need to stop at 2 HMAC keys/columns. You can have a Triple HMAC Strategy or a Quadruple HMAC strategy if that suits your application requirements. The concept is
the same, but at that point you may as well go with the List HMAC Strategy instead. -->
