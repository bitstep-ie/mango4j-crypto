# Application Level Encryption

## Introduction

This documentation is aimed at providing a more general discussion of implementing encryption in your code.

Much of the contents in this document can be
used as a reference for developers who need to implement ALE regardless of whether they use mango4j-crypto or not.
Developers should consider the guidelines documented in each section when building their own solutions.

This documentation purposely avoids talking about specific cryptographic implementations. or standards (AES, PKCS#11,
AWS KMS, etc.) because the core focus here is to talk about how
to implement ALE (whatever cryptographic methods, standards or providers you use) and what general challenges exist
along with guidance on overcoming them in your application.

This documentation uses some terms regularly which we'll define upfront:

*Tenant:* A term used to describe logical isolation in your system for a particular client entity. e.g. Some
institutions have requirements that any confidential data of theirs that you
store in your system should be segregated from data belonging to other entities. An application could spin up a full
environment just for that client institution or they can choose to
introduce the concept of 'tenants' in the system. With each client entity being a 'tenant' and each 'tenant' using their
own encryption keys, the application meets the data
segregation guidelines. If you do not use tenants then just consider your application as the tenant.

*HMAC key:* A [HMAC](faq.md#whats-a-hmac) is just a [hash](faq.md#whats-a-hash) which uses a secret key to create the hash.
HMACs are used for 2 main purposes in an application:

1. To support searching on fields that are encrypted
2. To support unique constraint enforcement on fields that are encrypted.
   The [FAQ](faq.md#why-do-i-need-to-hmac-data-in-order-to-make-it-searchable) section at the bottom of this document
   explains this in more detail.

## Mango Crypto-Key Driven Design

Often when designing applications which have to implement Application Level Encryption (ALE) it might seem to make sense
to
design only with some specific
cryptographic provider in mind (e.g. Azure Dedicated HSM) but doing this could introduce complexities later if your
application needs the potential to use different providers (different regions might have
different cryptographic providers or regulations). You may need to perform a [key rotation](faq.md#what-is-a-key-rotation)
from one key which uses some cryptographic provider to a new
key which uses some other cryptographic provider. Or even just rotate a key to a stronger algorithm, or whatever. So a more flexible design should be used to support a more generic
approach to implementing ALE. We call
the approach that the mango4j-crypto takes 'Key Driven Design'. The term 'Key Driven Design' comes from the fact
that each tenant has a group of encryption/HMAC keys (referred
to in this documentation as CryptoKeys) and those CryptoKeys define how the encryption operation is carried out. i.e. If
a CryptoKey has a type of 'AWS_KMS' then this library would use
AWS KMS and its SDK to perform the encryption operation, if a CryptoKey has a type of 'HSM' then this library will use
some matching HSM implementation to perform the encryption operation. This
approach hides the details from the application code which is generally good practice and allows for more flexibility if
an application needs to use a different method to perform
encryption later without needing any changes to existing application code.

This library was designed to force application code into a tried and tested design for ALE
which removes references to
specific cryptographic providers from your code and allows you to handle encryption key rotation and HMAC key rotation
more robustly. HMAC key rotation has a
long section all of its own in this document which should be considered mandatory reading for all developers who need to
HMAC data for lookup or unique constraint purposes.



