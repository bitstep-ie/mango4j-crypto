
# Annotations

The main annotations that developers will use are:

## @Encrypt

The @Encrypt annotation should be placed on fields which must be encrypted. This annotation also requires the
@EncryptedData partner annotation to be placed on the (single) field
where the library should put the resulting ciphertext (which is generated in one go for all fields), so you only need
one @EncryptedData field regardless of the number of @Encrypt
fields. This is shown in the example entity code below.

> **NOTE**: All fields marked with @Encrypt must be transient or the library will throw an error on registration of the
> entity. The only exception to this is when also using the @EnabledMigrationSupport annotation during once off
> migration
> onto the library for existing applications (this will be explained further in this document).

## @Hmac

The @Hmac annotation should be placed on fields which must be HMACed for either lookup or unique constraint purposes.
Depending on the HmacStrategy that your entity is using there needs to be corresponding fields where the library should 
write the HMACs to. There are currently 3 HMAC strategies supported by the library and each one has slightly different 
approaches related to the design of your entity. This will most certainly seem strange, but they will be
discussed at length further in this documentation when it will make more sense. Also, if you're familiar with the
challenges mentioned in the [the official Mango4j-crypto general documentation](../general/general.md)
they will make more sense.

> **NOTE**: All fields marked with @Hmac must be transient or the library will throw an error on registration of the
> entity. The only exception to this is when also using the @EnabledMigrationSupport annotation during once off
> migration onto the library for existing applications (this will be explained further in this document).

## @EncryptedData

As discussed above, if you have any fields marked with @Encrypt then you must have a single field marked with
@EncryptedData where the library will store the ciphertext for all
encrypted source fields. Underneath the hood, the library serializes all original fields into a single JSON structure 
which it then encrypts in a single operation.   

## @EncryptionKeyId

This is an optional annotation which you can place on a (String) field in your entity and the library will set
it to the ID of the crypto key that was used to perform the
encryption. This is not necessary for decryption purposes (the CryptoKey.key ID is also stored inside the @EncryptedData
anyway) but it is useful for more performant rekey query purposes so it's recommended to have this anyway
as it won't hurt and can be useful later.
It would basically be used to find the records which are (or aren't) using a certain encryption/HMAC key so that they can be
rekeyed with the current encryption key.