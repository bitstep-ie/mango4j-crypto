# mango4j - Change log

## 2.11.0

* Feature/GP-470 Create Cached Wrapped Key Implementation
* Converted docs from .adoc to .md


## 2.10.0

* PIT fixes

## 2.9.0

* Encrypt array support

## 2.8.0

* Feature/add cause when exception caught

## 2.7.0

* Update CLASS_INFO_MAP to ConcurrentHashMap

## 2.6.0

* Feature/bug fix add null check to collection ops
* Cascade encrypt support

## 2.5.0

* Updated maskers to support the new @Mask annotation

## 2.4.0

* Fix duplicate || condition
* Added Sonar exclusion for java:S3011
* Added support for serialization function callback
* UUIDv7 implementation
* Improved ObjectMutator Enum Handling to fix Accessor Exception in java 21

## 2.3.0

* Feature/remove crypto key type replace with string
* Feature/constructor injection cleanup

## 2.2.0

* Use cipher_text as the encrypted node name for consistency with real encryption delegates

## 2.1.3

* Feature/supress sonar warning iv spec
* Revert version to 2.1.3-SNAPSHOT
* Split out delegates to their own libs, non prod delegates are in their own lib
* Feature/compound unique constraints

## 2.1.2

* Finicity profile for manual deployment to Finicity artifactory

## 2.1.0

* Feature/fix non public wrapped key constructor

## 2.0.1

* PBKDF2ENncryptionService/WrappedKeyEncryptionService
* Dependency Updates
* Codebase internal improvements
* Sonar code smell fixes

## 2.0.0

* Reduce deps for mango utils, two new modules, validation and hibernate proxy resolver
* Java 17 & Dependency upgrades
* Feature/test tidy up

## 1.13.0

* Feature/ciphertext container map
* Feature/ioc friendly configuration
* Improving test quality
* Remove dependency on apache commons text

## 1.11.0

* Reflection instantiation of HMAC strategies

## 1.10.0

* Reflection instantiation of HMAC strategies

## 1.9.0

* Crypto key start time support

## 1.8.0

* Documentation upgrades

## 1.7.0

* Compatibility page
* Readme improvements
* Fix conformer issue with members in base classes not being processed
* Reflection updates
* Added support for multiple CipherTextFormatters

## 1.6.0

* Hash tokenizers
* Using correct MC catalog TA UUID
* Addition of initial mango4j-reflection module
* hashing strategies
* Docs enhancement and restructuring
* Completed Code Coverage

## 1.5.0

* Feature/mango4j crypto
* Feature/docs
* Feature/crypto core
* Documentation restructure
* MapMessageFormat started, lots more tests and then PIT to do

## 1.4.0

* Fixing pit tests

## 1.3.0

* PIT test improvements
* Relax type4 uuid validation

## 1.2.0

* Testing enhancements

## 1.0.0

* Initial collections
* Initial utils
* Backport all old style mango libraries