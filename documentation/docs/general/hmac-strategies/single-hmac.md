# Single HMAC Strategy

This strategy is only recommended if you're aware of the challenges mentioned above and are confident that they do not
apply to your application.
The Single HMAC strategy isn't really much of a strategy, it's just the way that many applications (unfortunately in
many cases) default to using HMACs. So for each HMAC you have a
single column in your table/record where you store the HMAC. So our USER_PROFILE table would simply look like this:

| ID                                   | TENANT_ID  | CIPHER_TEXT                                                          | SOME_OTHER_NON_CONFIDENTIAL_ATTRIBUTE | USERNAME_HMAC                | ENCRYPTION_KEY_ID                    | HMAC_KEY_ID                          |
|--------------------------------------|------------|----------------------------------------------------------------------|---------------------------------------|------------------------------|--------------------------------------|--------------------------------------|
| 9c7e275e-3729-421c-a7c5-cf02bba17f2d | MyTenantID | QmFzZTY0RW5jb2RpbmdPZlVzZXJQcm9maWxlQ29uZmlkZW50aWFsQXR0cmlidXRlcw== | some value In the clear               | QmFzZTY0VmFsdWVPZlVzZXJuYW1l | 23a0a1b4-3897-4eaa-b8fa-1818a9540f0c | 31ae30a7-4228-40a9-9078-d5e994491981 |

And (as usual) you have a list of HMAC keys on a tenant.
However, as mentioned previously this strategy exposes you to the 2 main challenges associated with HMAC key rotation.

Those challenges can still be dealt with using this strategy but the trade offs may not be worth it. Let's explore:

## Search challenge solution
The 1st of the HMAC challenges (search outage) can be dealt with in a fairly simple manner by introducing the concept
of a "HMAC key start time". When a new HMAC key is introduced into the system we could set this key start time to
"the current time + the key cache time". Then we make sure that the application never performs write operations with
that key until after the "key start time". An application would always use all of the HMAC keys it knows about to
perform search operations (regardless of key start times). But since no application would create/update a record with
the new key until all instances know about that key then all instances should be able to find all records including
new/updated ones.

## Unique constraints challenge partial solution

For the 2nd challenge (unique constraint integrity) it can only be narrowed down to a race condition but even then, only
by using a costly trade-off (in addition to using the "key start time" concept): forcing the application to perform a search before every write operation.
<br>
Let's elaborate with the username scenario:
<br>
<br>
Before every write operation the application will search (using all HMAC keys) to see if a record already exists with
that username.
<br>
. If the record exists then prevent the operation
<br>
. If the record does not exist then carry out the operation.
<br>
This solution will be unacceptable to many applications as the necessity of performing a search operation before every
single write operation will have a negative impact on performance. As an aside, it also makes any unique constraint
definitions on the database irrelevant for most cases (but not all - so they're still needed).

Imagine the following scenario (for even just a single instance application):
<br>

* Username `john.doe@test.com` is not in the system
* A new HMAC key has been created in the application with a valid key start time
* A request comes in to create a new record for username `john.doe@test.com` (on thread 1) 1 millisecond _<ins>before</ins>_
  "key start time"
* Thread 1 searches for username `john.doe@test.com` with both HMAC keys
* Username with that HMAC doesn't exist so Thread 1 doesn't find it
* Thread 1 decides to insert record using HMAC key 1 (since it's still before the "HMAC key start time")
* Thread 1 gets paused before insert
* A request comes in to create a new record for username `john.doe@test.com` (on thread 2) 1 millisecond _<ins>after</ins>_
  "key start time"
* Thread 2 searches for username `john.doe@test.com` with both HMAC keys
* Username with that HMAC doesn't exist so Thread 2 doesn't find it
* Thread 2 decides to insert record using HMAC key 2 (since it's now after the "HMAC key start time")
* Thread 1 wakes up and inserts the record with HMAC key 1
* Thread 2 inserts the record with HMAC key 2
* Username `john.doe@test.com` is now duplicated in the system


As mentioned previously the Single HMAC Strategy should only be used for applications which do not use HMACs for unique
constraint requirements. Even then there's a better strategy for not only unique constraint integrity but also for
a more powerful search support. But please consider the challenges above when deciding which HMAC strategy is right for your application.

<br>
<br>

**Pros of the Single HMAC strategy:**

- Probably the simplest design possible for supporting HMACs in an application
- Relational DB friendly, single table design
- No performance impact on write operations. Only calculates and inserts a single HMAC (per attribute)
  for each write operation
- Not much of a window for process (human) error during a key rotation or re-keying job.

**Cons of the Single HMAC strategy:**

- Cannot support applications which require both unique constraint enforcement and key rotation without serious drawbacks.
- Without "key start time" a key rotation will cause intermittent search outages for applications which cache HMAC keys.
- Without "key start time" unique constraints cannot be supported.
- Even with "key start time" unique constraint support requires performance degradation.
- Can never fully support unique constraint integrity under all circumstances.
