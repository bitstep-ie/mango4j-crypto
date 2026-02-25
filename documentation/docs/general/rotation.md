# Key Rotation (Changing the key)

Key rotation is the process of changing a CryptoKey to a new CryptoKey. After a key is rotated, create and update
operations should use the new key to perform the encryption operations. After a key is rotated, some records will have
been encrypted with the previous key (or keys) while some will have been encrypted with the new key. So previous keys
should still be
available for decryption until there are no more records associated with them.

When applications implement Application Level Encryption, they will commonly have to support key rotation.
They may have different requirements around how often the CryptoKeys need to be rotated or what conditions trigger a key
rotation.
But a key rotation should be something which an application can do at short notice on the fly. This is necessary to
ensure that no more ciphertext is generated with an old key after we have introduced a new key into the system.
Although rotating an encryption key is relatively straight forward, rotating a HMAC key on the other hand can pose
considerable challenges (discussed at length further in this documentation)

## Encryption Key Rotation

Changing an encryption key is relatively straightforward. Just add the new encryption key to your tenant/system and use
it for all write operations going forward. Just make sure to keep the older encryption keys available until no more
records exist that were encrypted with those keys. This is also why mango4j-crypto includes the CryptoKey ID in the
ciphertext that it generates, so that we always know what key we need to use to decrypt any given piece of ciphertext.

## HMAC Key Rotation

HMAC key rotation is a completely different beast and supporting it successfully requires serious application design
considerations. Due to this material being so involved we've given it a large section all of its own further in this
document.
Please read the discussion carefully.

## Rekeying (re-encrypting existing records with the new key)

Rekeying is the process whereby after a key rotation we have a background task which decrypts existing records
(that were encrypted with some older key) and re-encrypt them with the new key.
This is done when you want to completely remove an older key from the system after a key rotation but there are still
older records which were encrypted (or have had HMACs calculated) with the older key.
In this scenario we cannot remove the older key until there are no more records that have been encrypted with that key.
So in order to support the removal of the old key we need to rekey the records which were encrypted with that key onto
the new key until there are no more records remaining which were encrypted with the old key.
Rekeying is an extremely important function which is needed to handle the scenario in which a key is no longer
considered secure, and thus we can no longer tolerate any records having ciphertext which used that key.

Mango4j-crypto supports 2 types of rekey modes which are specified using the rekeyMode field on a CryptoKey
(please see the relevant section on how to configure the mango4j-crypto automatic rekey job):

**KEY_OFF:** This type of rekey is where we have some encryption/HMAC key that we want to completely remove from our
system but there might still be some entities which used that key.
> **NOTE:** If rekeyMode is set to 'KEY_OFF' on the current encryption or current HMAC CryptoKey it is ignored.
> It doesn't really make sense to key off the current key.


**KEY_ON:** This type of rekey is where we want all other encryption/HMAC keys (apart from this one) to be completely
removed from the system. This type of rekeying should be strongly reconsidered before initiating it because it will most
likely
rekey a very large portion of your entities which may have a notable impact on performance. Also, keep in mind that you
may need to make
sure any external cryptographic providers that you use are aware that they will experience a higher volume of traffic
for the period of time that the rekey takes.

> **NOTE:** If rekeyMode is set to 'KEY_ON' on a key that is not the current encryption or current HMAC CryptoKey it is
> ignored. It doesn't really make sense to rekey everything onto some old key.

**IMPORTANT: Avoid falling into the trap of thinking that shorter data retention rules can save you from having to
support
rekeying functionality in your application. We've often heard the idea that if an application has a key period of say 10
years but
our data retention period is only 5 years that rekey support will not be required and we can just swap the key every 10
years.
An easy way to see the flaw in this logic is to ask yourself what happens in year 11 when you change the HMAC key?
What about all the records from year 6 to year 10? You now can't find them! Also, with unique constraints you have 5
years of records in your system which may be at risk of duplication.**

### HMAC Key Rotation Challenges

The following section documents the 2 core challenges when it comes to supporting HMAC key rotation in your application.
It's advised for all developers not familiar with this particular topic to read this section very carefully.
It may seem easy to not give much attention to the scenario of rotating HMAC keys, possibly thinking _"when are we
really going to need to change a [tenant's](faq.md#Whats-a-tenant) HMAC key?!"_ or _"I can worry about it later"_. But
hopefully as you
can see below, in order to support this functionality there are very important considerations to take into account for
the way that you design your application. And the challenges presented by HMAC key rotation can be very difficult to
retrofit into an application further down the line.

#### Searching operations after the rotation of a HMAC key

If your application has the concept of a single HMAC key per tenant, it's extremely likely that you'll need to stop
doing this and change this design approach. Unless for some reason you don't have to support HMAC key rotation in your
application.
The reason being that if you change a tenant (or system) HMAC key during normal application operation you won't be able
to find any of the existing records.
The only way that you could change a tenants HMAC key is if it's acceptable to take your system offline until all
records have been re-keyed with the new key by some background job. Or (for some reason) you are able to tolerate a lot
of search misses for existing records until such a background job was complete while the application was running.
Both of these scenarios are very unlikely to be tolerated in most modern applications.

To break down this sample scenario into steps:

1. You change the HMAC key for your tenant.
2. All application searches going forward will use the new HMAC key.
3. Immediately you won't be able to find any records in your system because all existing HMACs have been calculated with
   the old HMAC key
4. You kick off a background job which goes from record to record decrypting and re-keying the fields with the new HMAC
   key.
5. Your application searches gradually start to become more and more successful over time.
6. Once the background rotation job is complete your application search functionality is now back online.

The functional search outage from your application is most likely unacceptable. Re-keying all records in your system may
take a very large amount of time. You may have a very large number of records in your system and even with a modest
number
of records, it's generally not acceptable to have this background re-keying job run as fast as it can due to
performance degradation of your system. Increased number of calls to the DB (2 extra calls in the background for every
record). Not to mention if you're using an external
cryptographic provider (like Azure Dedicated HSM) it might not handle (or even allow) the extra traffic without its own
performance problems.
It may be tempting to think along the lines of running the background job until all records are re-keyed with the new
HMAC key before changing the key on the tenant. But this is just the same scenario in reverse. Your application searches
will begin successfully but immediately will become less and less successful over time until the background job is
finished and you change the tenants HMAC key to the new one.

To remedy this you need to implement 2 simple concepts:

1. Change your design approach so that a tenant has a <ins>**list**</ins> of HMAC keys rather than a single HMAC key.
   Depending on your application requirements this list may contain anywhere from a single HMAC key to N HMAC keys.
   During HMAC key rotations you will _add_ the new HMAC key to the list, instead of _replacing_ the old HMAC key.
   If your application doesn't support rekeying then this list of HMAC keys will keep getting larger until one
   of the following 2 scenarios happen:
   <br>
   a). Older data that has HMACs calculated with an old key is deleted due to data retention rules. Once there are no
   more HMACs in the DB that were calculated with that old HMAC key, it can be removed from the list.
   <br>
   b). You rekey all records onto the new HMAC key. HMAC Rekeying can get tricky and there are multiple ways of doing it
   depending on which HMAC strategy you use (described below).

   <br>
2. For your application's search operations, change the logic to look for matches with a _list_ of HMACs instead of
   trying
   to match a single HMAC. The number of HMACs generated for the search will be equal to the number of HMAC keys in the
   tenants HMAC key list.
   So your code needs to be prepared for this scenario by matching across a list of HMACs rather than a single HMAC.

So the steps for converting your design approach to accommodate the above approach would become:

1. Update your tenant record to have a list of HMACs
2. Modify your application search code in such a way that instead of looking for a HMAC field value equal to the
   generated HMAC (e.g. in JpaRepository):

```java
findByUsernameHmac(String userNameHmac);
```

Change it to generate a list of HMAC values (using the tenant's _list_ of HMAC keys) and look for a HMAC value which is
in that list of HMACs (e.g. in JpaRepository):

```java
findByUsernameHmacIn(Collection<String> userNameHmacs);
```

3. Modify your normal application HMAC code for *_write_* operations to choose the active HMAC key for the HMAC
   operations from the tenant's HMAC key list (that would be the HMAC key with the most recent CryptoKey.createdDate
   field).

**However, the previous solution still has major flaws!**

If your application is a multi-instance application and caches key information (both very likely in modern applications)
then very big issues still remain.
<br>
Even with the previous solution consider the following scenario:

#### Multi-instance application with cached Keys search scenario

1. You have 2 instances of your application, and they both cache key/tenant information (common practice because this
   type of
   information rarely changes)
2. You add the new HMAC key to the tenant's list of HMAC keys
3. You kick off a background rekey job
4. Instance 1 of your application has not updated its cache and is still only seeing the tenant with the old HMAC key
5. Instance 2 of your application has updated its cache and is now seeing the tenant with both the old HMAC key and new
   HMAC key
6. Instance 2 inserts a new record with an email of `john.doe@test.com` and uses the new HMAC key to do it (since going
   forward the application should use the new HMAC key)
7. A search comes into instance 1, and it uses the old HMAC key to HMAC `john.doe@test.com` and search for it.
8. The record is not found because the HMAC for `john.doe@test.com` was calculated and inserted by instance 2 using the
   new HMAC key

To solve this issue, another design change needs to be considered. This change is described in the next section
and is also needed for another (possibly much more serious) challenge regarding unique constraints. Implementing the
design consideration in the next section will also solve the
above shortcoming.

#### Unique constraint enforcement after the rotation of a HMAC key

> * IMPORTANT!!! - This problem is much more important than the previous search problem! If your application has unique
    constraints on
    confidential fields then there's a chance that changing a HMAC key could leave your application in a broken state!

If you have a confidential field which you need to be unique for your tenant, let's say....a username field. Then you
will have a DB column with a unique constraint where you store the HMAC of this username. Now, if you switch HMAC keys
it will be possible to create accounts with the same username. Since an existing account username was calculated with
the old HMAC key then a new account could be created with the same username since now that the new HMAC key is being
used it
will calculate a different HMAC for the same username value and <ins>the DB unique constraint will **_not_** be
enforced</ins>.
This could have serious repercussions for your system and its data integrity.

To break down this sample scenario into steps:

1. A user exists in your application with username `john.doe@test.com`
2. You change your tenant's HMAC key to the new HMAC key (or if you've followed
   the [above](#Searching-operations-after-the-rotation-of-a-HMAC-key) approach
   to solve the search challenge, you've added the new HMAC key into your tenant's list of HMAC keys)
3. A request to create a new user (or change an existing username) is sent to your application with the username
   `john.doe@test.com`.
4. Your application calculates the HMAC of `john.doe@test.com` using the tenant's new HMAC key. This HMAC will be
   different than the username HMAC for the existing `john.doe@test.com` record.
5. The new record is created (or existing record is updated) successfully as the unique constraint on that DB column
   won't have been triggered.
6. There now exists 2 users in the application with the username `john.doe@test.com`

It may be tempting to think that you can offset this somewhat by always searching for the username first before write
operations but this impacts performance and makes the DB unique constraint a little bit redundant.
However, in any case it doesn't solve the problem. In multi-instance applications which cache key information
there would still exist a race condition in your code which can result in 2 usernames with the same value:

* Imagine at [point 7](#multi-instance-application-with-cached-keys-search-scenario) in the previous cached keys search
  scenario that instead of
  _searching_ for a record, instance 1 _creates_ a new record with the
  username `john.doe@test.com`. It can even search for any existing records but it won't find them (because it doesn't
  yet
  have the latest HMAC key). This situation will result in a duplicate record being created by instance 1.

To remedy this you need to implement particular approaches to calculating and storing the HMACs for your entity fields.
The following sections detail some of these approaches, all of which are supported in
the [mango4j-crypto](https://github.com/bitstep-ie/mango4j-crypto) library.
