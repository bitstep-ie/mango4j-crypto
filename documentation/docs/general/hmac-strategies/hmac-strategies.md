# HMAC Strategies

There are several designs you can choose to work with HMACs in your code depending on your application's ability to
tolerate or circumvent the challenges documented above (if they apply). So this section will discuss the ones supported
by Mango4j-crypto in the following sections. We strongly advise considering the [List HMAC Strategy](list-hmac.md) but 
due to its unfamiliarity we've documented three different strategies:

- [Single HMAC Strategy](single-hmac.md)
- [List HMAC strategy](list-hmac.md)
- [Double HMAC strategy](double-hmac.md)


## Some final considerations for application designs

Although corporate security guidelines in some companies may only require applications to support HMAC key
rotation but not necessarily rekeying, we strongly advise application developers to reconsider this in the context of
their application functionality and requirements! Supporting only HMAC key rotation for long-lived data means
that there's a strong possibility that you cannot ever deprecate any of a tenant's HMAC keys. Every time you update a
tenant to a new HMAC key (meaning that you add a new one into the tenant's list of keys) then your application's
search operations will progressively get slower. This is because if a tenant has N HMAC keys we have to calculate N
HMACs when we search for something. Since we can't remove a tenant's keys (because there may be records that have never
been modified since being written with the key in use at that time) then we'll have to keep using all of them to
generate HMACs for every operation until the end of time.
Also, although the search challenge documented in the [key rotation section](../rotation.md) will still be solved in a 
functional sense, the unique constraint challenge will still remain a serious problem in your application (if you have unique constraint
requirements).
The only concrete way to solve the unique constraint challenge for key rotation without rekey would be to use
the [List HMAC Strategy](list-hmac.md).