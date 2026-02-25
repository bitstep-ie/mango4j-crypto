# Frequently Asked Questions

## What's a tenant?

For applications which store data from different client applications or enterprises there is often the requirement that
we need to segregate the data belonging to each client (i.e. your application has multiple customer enterprises which
use it: Bank A, Bank B and Bank C).
<br>
Company requirements (and regulations) can sometimes dictate that the data which your application stores related to each
of these customers must be logically separated from each other. This is to limit the exposure which might happen in a
security breach. Your application could spin up 3 separate (and isolated) environments for each customer but this is
often
too costly to maintain.
<br>
An easier and equivalent way to do this is to have the concept of 'tenants' in your application. Each customer is a '
tenant'
and each tenant has separate encryption keys. So your application will store and configure tenant information (which
will
include the details of encryption and HMAC keys for each tenant).
<br>
Each operation in your application will then be within the context of one of these tenants. Any data stored
for Bank A is encrypted with an encryption key which is _only_ used by Bank A, And similarly, any data stored
for Bank B is encrypted with an encryption key which is _only_ used by Bank B. If your system doesn't have/need the
concept of tenants then you can just think of a tenant as "the application" in this documentation.

## What's a HMAC?

A HMAC is just a hash which uses a secret key to perform the hashing operation.

## What's a hash?

A hash is a one-way encryption cipher. One-way means that for a given piece of data, hashing it will produce a
ciphertext
but that ciphertext can never be used to reproduce the original value, it can never be decrypted. Hashes are useful for
storing data that needs to be matched but which we never want to risk an attacker knowing. Hashes are often used to
store
passwords in a secure system.

## What's an IV?

An IV (Initialization Vector) essentially introduces randomness into the data being encrypted. A new IV should be
generated and used for every encryption operation which means that even if you encrypt the same piece of data with the
same
secret key, the resulting ciphertext will be different. The ciphertext will always decrypt successfully to the original
data (the IV is actually stored in the clear, inside the data containing the ciphertext) but the fact that the resulting
ciphertext is
always unique for any encryption operation makes cryptanalysis more difficult to potential attackers.

## Why do I need to HMAC data in order to make it searchable?

When we encrypt a piece of data we should use an [IV](faq.md#Whats-an-IV) as well as the secret key - so make sure to
consider using IVs in any custom EncryptionServiceDelegate implementations you create for your application.
Due to the fact that each time we encrypt a piece of data it never generates the same ciphertext this means
that we cannot search on that attribute. It may be tempting to think that for a search operation you could encrypt the
incoming search value and look for matching ciphertext in the DB. But since the ciphertext just generated for the
incoming
search term is guaranteed unique (due to the use of an IV) it won't match anything. The solution is to store a HMAC
value alongside any attribute that needs to be searchable. HMACs will always give the same HMAC value for the same piece
of data so they can be used for search purposes. If an encrypted attribute also has a HMAC value stored separately for
it,
Their irreversibility makes them very secure.

## Why do I need to HMAC confidential data in order to make it unique?

As explained above the encryption of confidential data always results in a unique ciphertext (due to the use of IVs) so
that particular ciphertext cannot be used to enforce a
unique constraint. The solution is to also store a HMAC for this attribute and place a unique constraint on that field
instead.

## What is a key rotation?

A key rotation is the action of changing an encryption or HMAC key that you're using right now (for a tenant) to a
different one.

## Why would I perform a key rotation?

Many corporate and regulatory guidelines require encryption keys to be updated when certain criteria are met. The
criteria definitions can sometimes be a bit fuzzy and there's no permanent concrete
criteria for all applications. Some criteria are usage based, e.g. changing the key after it's been used X times. Other
criteria are time based, e.g. change the key every X period.
Please consult your corporate security guidance or the appropriate regulations for prescriptions on when you need to
rotate encryption and HMAC keys
in your application.

The following points should also be taken into consideration when deciding when a key might need to be rotated:

* If a key becomes compromised then it is necessary to remove it from the system, which requires rotating to a new key
  (most likely followed by a rekey). This could happen at any time.
* If new company or national regulations decide that the crypto period needs to be some different prescription than
  current company/regulatory requirements.
* Some Cryptographic providers may stop being available in certain regions or deployment environments. In that case,
  application instances deployed in those environments will have
  to rotate keys onto a different cryptographic provider.

## What does re-keying mean?

Re-keying is where after introducing a new encryption/HMAC key, some background job goes through the
database record by record, decrypting (with the old key) and re-encrypting (re-keying) with the new key(s) until there
are no more records left that use the old key(s).

## Why should I re-key?

If an encryption or HMAC key is compromised then you'll probably have to make sure that no data in your DB is encrypted
or contains HMACs calculated with that key. This means you
have to consider re-keying all the data that used that compromised key with a new encryption/HMAC key.
If your application uses HMACs for data that has a long data retention policy then it's probably unrealistic to keep
adding more and more HMAC keys over time but never being able
to remove them from the system. With each addition of a HMAC key the performance of your application will degrade
because that's one extra HMAC to calculate (and search for/and
possibly store) for every HMAC operation.
If your application is multi-instance, caches keys and doesn't use the List HMAC Strategy then you'll need to re-key if
your application uses HMACs for unique constraint
enforcement.

## Why does mango4j-crypto-core have the concept of only 1 encryption key but multiple HMAC keys?

When a piece of data is encrypted a reference to the encryption key is contained in the actual ciphertext along with the
encrypted data. This means that it will always be possible
to decrypt the data even if the current encryption key is changed (i.e. for a key rotation), assuming you didn't delete
the old key. HMACs however are
different, [HMACs don't have a reference to the HMAC key stored alongside them.](faq.md#Why-dont-HMACs-have-a-reference-to-the-HMAC-key-stored-alongside-them-the-same-way-encrypted-ciphertext-does)
So, once a HMAC key is updated/rotated to a new HMAC key, some
records will have HMACs calculated using the old key (since they haven't been recalculated yet) and some records will
have HMACs calculated using the new key (new records and newly
updated records). This means that there will be periods where we need to perform searches using more than 1 HMAC key
since we can't be sure what records have been calculated with
what keys unless all HMACs in the DB are recalculated with the new key (re-keyed). This is just a re-statement of the
HMAC key rotation challenges.

In a simpler statement: To decrypt something, we have already obtained the data we need to decrypt. But HMACs are used
to _search_ for data, we don't know where it is yet.
Therefore, we don't know which HMAC key might have been used to HMAC it. So we have to try all the HMAC keys to search
for it.

## Why don't HMACs have a reference to the HMAC key stored alongside them the same way encrypted ciphertext does?

Elaborating on previous statements: It would serve no real purpose to store a reference to the HMAC key beside the HMAC
since they are used primarily for search purposes and by
definition that means that you have no information about the row where the HMAC is or even where it is in the DB. With
encrypted ciphertext it's different, you already know the
row (maybe your application accessed it directly by ID, or maybe you've searched for and found it). So once you have the
row then it's good that it has a reference to the
encryption key that was used, so now you can use that key reference to decrypt it. With HMACs you're trying to use them
to find
the row in the first place and once you've found the row,
having a reference to the HMAC key would serve no extra purpose. In summary, you never know where the HMAC you're
looking for is or which HMAC key might have been used to calculate
it, so storing the HMAC key reference alongside it won't help you with anything. And again, This is why you must try all
possible HMAC keys when searching.

*Caveat:* In saying that, it is useful to store a reference to the HMAC key alongside the HMAC so that re-key jobs can
easily query which records need re-keyed and which do not. But this is a
convenience related to re-keying performance only and is not related to normal HMAC functionality.

## What is HMAC tokenization?

HMAC Tokenization is the process of chopping an input value into separate pieces and calculating HMACs for each piece
for more flexible search support. i.e. for a PAN (Primary Account Number - such as Credit Card numbers) you could
HMAC the full PAN, HMAC the last 4 digits of the PAN, HMAC the PAN without dashes/spaces giving a total of 3 resulting
HMACs for a single input. This allows you to support richer
search capabilities because now your application can support searching on the last 4 digits of the PAN and allows
searches to find a PAN whether it has dashes/spaces in it or not.