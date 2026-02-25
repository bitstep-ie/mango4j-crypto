# HMAC

## HMAC Strategies

A core concept in the mango4j-crypto library is that of HMAC strategies. There are various ways that an application
could choose to implement key-rotation friendly HMAC functionality (please read the 
[general documentation](../general/general.md#hmac-key-rotation-challenges) for a detailed
explanation of this material) and this library provides 3 
[HMAC Strategies](../general/general.md#hmac-strategies) out of the box.

You can choose which ones to apply to your application entities by using the corresponding class level annotation. The
library authors strongly advise application developers to consider
the @ListHmacStrategy unless there are strong reasons not to. Currently, the library supports the following (in
order of preference of the mango4j-crypto team):
- [@ListHmacStrategy](#list-hmac-strategy)
- [@SingleHmacStrategy](#single-hmac-strategy)
- [@DoubleHmacStrategy](#double-hmac-strategy)

But we'll start with the Single HMAC Strategy as that's the easiest to understand. In this example we also need to 
generate HMACs for both the pan and username fields as they both need to be searchable and username needs to be unique 
in our application.

### Single HMAC Strategy

```java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity(name = "USER_PROFILE")
@SingleHmacStrategy
public class UserProfileEntity {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	@Hmac
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	public String getPan() {
		return pan;
	}

	public void setPan(String pan) {
		this.pan = pan;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getEthnicity() {
		return ethnicity;
	}

	public void setEthnicity(String ethnicity) {
		this.ethnicity = ethnicity;
	}

	@Id
	@Column(name = "ID")
	private String id;

	@Column(name = "FAVOURITE_COLOR")
	private String favouriteColor;

	@Column(name = "USERNAME_HMAC", unique = true)
	private String userNameHmac;

	@Column(name = "PAN_HMAC")
	private String panHmac;

	@Column(name = "ENCRYPTED_DATA")
	@EncryptedData
	private String encryptedData;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}

}
```

> **NOTES**:
> * We've added the @SingleHmacStrategy annotation to the class.
> * We've added 2 new fields 'panHmac' and 'userNameHmac' to the entity. This is because HMACs need to be stored separately, 
>   and the convention the SingleHmacStrategy uses is that the hmac fields must be named the same as the source fields 
>   with the suffix 'Hmac'. So the 'pan' field gets its HMAC calculated and set into the 'panHmac' field and same for userName.
> * Again, you'll notice that we didn't bother defining getters/setters for the USERNAME_HMAC, PAN_HMAC fields either, 
>   for the same reason that we didn't bother defining getters/setters for the ENCRYPTED_DATA field.
> * The panHmac and userNameHmac fields are persisted to the DB in our example and each have their own columns 
>   (we're using Hibernate here). 
> * The USERNAME_HMAC also has a unique constraint on it.

<br>

### List HMAC Strategy


```java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.ListHmacStrategy;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;
import ie.bitstep.mango.crypto.domain.Unique;
import ie.bitstep.mango.crypto.tokenizers.PanTokenizer;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@ListHmacStrategy
@Document(collection = "UserProfile")
public class UserProfileEntityForListHmacStrategy implements Lookup, Unique {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	@Hmac(purposes = {Hmac.Purposes.LOOKUP, Hmac.Purposes.UNIQUE})
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	private Collection<CryptoShieldHmacHolder> lookups;

	private Collection<CryptoShieldHmacHolder> uniqueValues;

	public String getPan() {
		return pan;
	}

	public void setPan(String pan) {
		this.pan = pan;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getEthnicity() {
		return ethnicity;
	}

	public void setEthnicity(String ethnicity) {
		this.ethnicity = ethnicity;
	}

	@Id
	private String id;

	private String favouriteColor;

	@EncryptedData
	private String encryptedData;

	@EncryptionKeyId
	private String encryptionKeyId;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}

	@Override
	public void setLookups(Collection<CryptoShieldHmacHolder> lookups) {
		this.lookups = lookups;
	}

	@Override
	public List<CryptoShieldHmacHolder> getLookups() {
		return lookups;
	}

	@Override
	public void setUniqueValues(Collection<CryptoShieldHmacHolder> uniqueValues) {
		this.uniqueValues = uniqueValues;
	}

	@Override
	public List<CryptoShieldHmacHolder> getUniqueValues() {
		return uniqueValues;
	}

}
```
<br>

The above example entity is designed for MongoDB (as it's the most suitable DB for this HMAC strategy). If you are using
it with an SQL DB check out the [mango4j-crypto-example](https://github.com/bitstep-ie/mango4j-examples/tree/main/mango4j-crypto-example) demo application which does the exact same for an SQL DB.

> **NOTES:**
> * Similar to the SingleHmacStrategy sample entity, the userName field is annotated with @Hmac but here it also has a 
>   'purposes' definition. This can have the values of Purposes.LOOKUP, Purposes.UNIQUE, or both depending on what purpose that field 
>   is being HMACed for. If no value is specified then it defaults to Purposes.LOOKUP.
> * The pan field also has the @Hmac annotation but no purposes definition so it defaults to Purposes.LOOKUP
> * Entities which use @ListHmacStrategy must implement either the Lookup interface, the Unique interface or both. Since this entity uses
    HMACs for both purposes it implements both interfaces. Having to implement these interfaces makes the List HMAC Strategy quite 
>   different from other HMAC designs and that is shown in your entity definition. But it's also what makes it the most powerful strategy.
> * Unlike the other HMAC strategies this one doesn't have associated target HMAC fields with the 'Hmac' suffix. Instead,
    it implements the methods getLookups() and setLookups() from
    the Lookup interface and the getUniqueValues() and setUniqueValues() from the Unique interface. The library calls back
    to these methods to get and set the HMACs. This is what
    makes this the most powerful HMAC strategy, we can have as many HMACS for as many keys or tokenized values as needed.
> * If you are using HMACs for unique constraint purposes, make sure to create the appropriate unique constraint definitions on your
    DB. Generally you would place a compound unique constraint on the columns representing CryptoShieldHmacHolder.alias 
    and CryptoShieldHmacHolder.value (and tenant ID if applicable).

> **Note:** When calling CryptoShield.encrypt() for entities which have been updated (as opposed to newly created),
> make sure that the setLookup() and setUniqueValues() methods _completely replace_ the existing lists! Do not append to
> the existing lists!!!

#### HMAC Tokenizers

If using the ListHmacStrategy for an entity you can make use of HMAC Tokenizers by specifying them in the @Hmac
annotation's HmacTokenizers method. Like:


```java
@Hmac(HmacTokenizers = {PanTokenizer.class})
private transient String pan;
```

The library will then generate a series of alternative HMACs for that field using those HmacTokenizer classes. For
example the PanTokenizer (which is included in the library) in
the sample code above will result in the lookup HMAC list for that entity including the HMAC of the last 4 digit of the
PAN, the HMAC of the first 6 digits of the PAN, the HMAC of
the PAN without dashes or spaces (if there are any). These alternative representations will then be stored along with 
the HMAC of the full original PAN that was supplied. The library has some standard HMAC tokenizers, please see the javadocs
for each one to learn what HMAC representations they generate. Applications can supply their own HmacTokenizers with
whatever tokenization logic they need by implementing the
[HmacTokenizer](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto/src/main/java/ie/bitstep/mango/crypto/tokenizers/HmacTokenizer.java) interface. 
If you have created a HmacTokenizer you think would be generally useful to others please let us
know and we'll add it to the library. Using HMAC Tokenizers
will help applications with more flexible searching functionality and is another reason that the ListHmacFieldStrategy
is the most powerful of the 3 core HMAC strategies.

##### Compound Unique Constraints With The List HMAC Strategy

One extra challenge when using the List HMAC strategy is that if you have a requirement of needing to create a compound 
unique constraint on a group of fields that include a HMAC field then this cannot be done the normal way. You can 
create these types of constraints using the 
[@UniqueGroup](https://github.com/bitstep-ie/mango4j-crypto/blob/main/mango4j-crypto/src/main/java/ie/bitstep/mango/crypto/hmac/UniqueGroup.java) 
annotation.  You can place this annotation on each field marked with @Hmac and give them all the same name and a unique 
order number (which you must never change!) and the library will calculate a single unique HMAC for them all.

> NOTE: Mixing HMAC and cleartext fields in a unique group is fine. But at least one field in the group must be marked 
> with @Hmac otherwise the library will throw an error on startup.

### Double HMAC Strategy

Please read the [the official general documentation](../general/general.md#double-hmac-strategy) for a description 
of the Double HMAC Strategy and for when you might want to use it. The entity definition when using it is similar to the 
one for the Single HMAC Strategy. Below is an example entity definition.

```java
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.DoubleHmacStrategy;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@DoubleHmacStrategy
@Entity(name = "USER_PROFILE_ENTITY_FOR_DOUBLE_HMAC_STRATEGY")
public class UserProfileEntity {

    @Encrypt
    @Hmac
    private transient String pan;

    @Encrypt
    @Hmac
    private transient String userName;

    @Encrypt
    private transient String ethnicity;

    public String getPan() {
        return pan;
    }

    public void setPan(String pan) {
        this.pan = pan;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getEthnicity() {
        return ethnicity;
    }

    public void setEthnicity(String ethnicity) {
        this.ethnicity = ethnicity;
    }

    @Id
    @Column(name = "ID")
    private String id;

    @Column(name = "FAVOURITE_COLOR")
    private String favouriteColor;

    @Column(name = "USERNAME_HMAC_1", unique = true)
    private String userNameHmac1;

    @Column(name = "USERNAME_HMAC_2", unique = true)
    private String userNameHmac2;

    @Column(name = "PAN_HMAC_1")
    private String panHmac1;

    @Column(name = "PAN_HMAC_2")
    private String panHmac2;

    @Column(name = "ENCRYPTED_DATA")
    @EncryptedData
    private String encryptedData;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getFavouriteColor() {
        return favouriteColor;
    }

    public void setFavouriteColor(String favouriteColor) {
        this.favouriteColor = favouriteColor;
    }
}
```

> **NOTES**:
> * We've added the @DoubleHmacStrategy annotation to the class.
> * This entity definition is almost the same as the one for SingleHmacStrategy except that each field annotated with 
>   @Hmac has 2 associated HMAC fields 'panHmac1'/'panHmac2' and 'userNameHmac1'/'userNameHmac2'. This is because 
>   with the Double HMAC Strategy we need 2 HMACs to be stored separately for each HMAC source field. 
> * Again, you'll notice that we didn't bother defining getters/setters for the USERNAME_HMAC_1, USERNAME_HMAC_2, 
>   PAN_HMAC_1 or PAN_HMAC_2 fields either, for the same reasons as mentioned before.
> * The panHmac1, panHmac2, userNameHmac1 and userNameHmac2 fields are persisted to the DB in our example and each have their own columns 
>   (we're using Hibernate here). 
> * The USERNAME_HMAC_1 and USERNAME_HMAC_2 each have a unique constraint on them also.
> * Application search code must look for matching HMACs in both of the HMAC columns associated with each HMAC source 
    field. So those queries become OR queries in the case of multiple HMAC keys in use. You can see the 
>   [mango4j-examples code](https://github.com/bitstep-ie/mango4j-examples/blob/main/mango4j-crypto-example/src/main/java/ie/bitstep/mango/examples/crypto/example/doublehmacstrategy/service/UserProfileService.java#L62) to see an example of what this might look like.

<br>
