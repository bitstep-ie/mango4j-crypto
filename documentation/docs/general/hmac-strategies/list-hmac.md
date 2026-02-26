# List HMAC strategy

This strategy documents the most general and powerful design that application developers can use to take care of all
problems mentioned above. Using this design guarantees your
application will accommodate HMACs correctly regardless of your use case or application requirements.
The List HMAC strategy has just 2 fairly elegant concepts:

1. Have a list of HMAC keys on your tenant, rather than a single HMAC key. Exactly as already discussed in this
   document.
2. For all write operations write the entire list of generated HMACs into your DB.

Part 2 is the tricky bit because when you use an SQL DB, it forces you into a particular entity design. If you take our
previous examples where we HMAC the username. This would
mean that we would have a table for the actual record (maybe a USER_PROFILE table) with the encrypted ciphertext and
whatever other information, a table for lookup HMACs if we are
using the username HMAC for search purposes (e.g. USER_PROFILE_LOOKUPS) and a 3rd table for unique values (
USER_PROFILE_UNIQUE_VALUES) if we are using the username HMAC to enforce
uniqueness per tenant.

For example the USER_PROFILE table might look like this:

| ID                                   | TENANT_ID  | CIPHER_TEXT                                                          | SOME_OTHER_NON_CONFIDENTIAL_ATTRIBUTE | ENCRYPTION_KEY_ID                    |
|--------------------------------------|------------|----------------------------------------------------------------------|---------------------------------------|--------------------------------------|
| 9c7e275e-3729-421c-a7c5-cf02bba17f2d | MyTenantID | QmFzZTY0RW5jb2RpbmdPZlVzZXJQcm9maWxlQ29uZmlkZW50aWFsQXR0cmlidXRlcw== | some value In the clear               | 23a0a1b4-3897-4eaa-b8fa-1818a9540f0c |

And the USER_PROFILE_LOOKUPS table would look like this:

| ID                                   | TENANT_ID  | ALIAS    | VALUE                        | HMAC_KEY_ID                          | USER_PROFILE_ID                      |
|--------------------------------------|------------|----------|------------------------------|--------------------------------------|--------------------------------------|
| 2f2ab2f4-57cb-441a-84c8-44eee23e3693 | MyTenantID | username | QmFzZTY0VmFsdWVPZlVzZXJuYW1l | 31ae30a7-4228-40a9-9078-d5e994491981 | 9c7e275e-3729-421c-a7c5-cf02bba17f2d |

And the USER_PROFILE_UNIQUE_VALUES tables would look like this:

| ID                                   | TENANT_ID  | ALIAS    | VALUE                        | HMAC_KEY_ID                          | USER_PROFILE_ID                      |
|--------------------------------------|------------|----------|------------------------------|--------------------------------------|--------------------------------------|
| eeddbee1-34db-4554-ada4-a23e04c69846 | MyTenantID | username | QmFzZTY0VmFsdWVPZlVzZXJuYW1l | 31ae30a7-4228-40a9-9078-d5e994491981 | 9c7e275e-3729-421c-a7c5-cf02bba17f2d |

The USER_PROFILE_LOOKUPS and USER_PROFILE_UNIQUE_VALUES look exactly the same because they are. The only reason they
need to be separate is because the USER_PROFILE_UNIQUE_VALUES
table needs a compound unique constraint placed on the TENANT_ID, ALIAS, VALUE and HMAC_KEY_ID columns, whereas the
lookup does not.

With the above entity design when inserting or updating records in the USER_PROFILE table, your application code would
generate a list of HMACs (1 for each HMAC key in use) and
insert them all into both the USER_PROFILE_LOOKUPS and USER_PROFILE_UNIQUE_VALUES tables (1 row per HMAC entry). If you
now go back to the HMAC challenge scenarios described
earlier in this document (even the cached keys scenario), you'll see that this design guarantees to overcome both.
If you're using a document DB such as Mongo, you should just implement this design anyway as it won't interfere with
your entity design. The USER_PROFILE_LOOKUPS and
USER_PROFILE_UNIQUE_VALUES tables just become separate lists inside the USER_PROFILE record. Unfortunately when using
relational DBs this strategy will require inserting/updating
from 1 to 3 separate tables for each write operation and for searching it will require a join from the
USER_PROFILE_LOOKUPS table back to the original record in the USER_PROFILE
table.

## Process for re-keying data with the List HMAC Strategy

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
   **common for passive key rotation**
5. For each record found, decrypt the record, calculate the HMAC(s) with the new key, insert the HMAC(s) into the
   lookup/unique constraint tables (or **_add_** them to the lists if
   using a document DB and save the record). Existing HMACs should remain as they are, untouched.
6. Wait for all applicable records to be re-keyed
7. Remove the old HMAC key from the tenant's list of HMAC keys
8. Wait until the HMAC key cache expiry time has passed (if applicable), so that all application instances are no longer
   using the old HMAC key.
9. For every record, remove all HMACs from the lookup/unique constraint tables (or document HMAC entries) that were
   calculated with the old HMAC key. Leaving them there won't
   affect functionality so this cleanup step is optional from a functionality perspective, but leaving old HMACs in your
   system is a potential security hazard so applications
   should perform this step at least for long-lived data.
10. You can now delete the old HMAC key from wherever it was stored.

**Pros of the list HMAC strategy:**

- Bulletproof HMAC design which will work for all combinations of application requirements
- The only general HMAC design which supports passive key rotation for long-lived data which uses HMACS for unique value
  enforcement
- Application search code becomes standardized and is cleaner (because all lookups tables will have the same definition)
- Excellent fit for document DBs (Mongo)
- Supports zero-outage search
- Supports unique constraint integrity
- Supports applications which cache HMAC keys
- Supports all passive key rotation designs
- Easiest strategy for supporting re-keying of data with no impact to application functionality
- Can have as many HMAC keys on a tenant as you want. You can add a new HMAC key anytime you want, even in the middle of
  a re-keying job, and it won't affect application
  functionality.
- Easily supports [HMAC tokenization.](../faq.md#what-is-hmac-tokenization)

**Cons of the list HMAC strategy:**

- Forces relational DBs into a multi-table entity design which can negatively impact performance
- Always adds/updates N HMACs for each write operation, where N is the number of HMAC keys in use. So depending on the
  rate at which an application deletes old keys this will have
  a performance impact if the list of HMAC keys keeps growing.
