package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.ListHmacStrategy;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;
import ie.bitstep.mango.crypto.domain.Unique;

import java.util.Collection;
import java.util.List;

@ListHmacStrategy
public class TestAnnotatedEntityForListHmacFieldStrategy implements Lookup, Unique {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	@Hmac(purposes = {Hmac.Purposes.LOOKUP, Hmac.Purposes.UNIQUE})
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	@EncryptedBlob
	private String encryptedData;

	@EncryptionKeyId
	private String encryptionKeyId;

	private String favouriteColor;

	private List<CryptoShieldHmacHolder> lookups;

	private int numberOfTimesAddLookupsWasCalled = 0;

	private List<CryptoShieldHmacHolder> uniqueValues;

	private int numberOfTimesAddUniqueValuesWasCalled = 0;

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

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	@Override
	public void setLookups(Collection<CryptoShieldHmacHolder> hmacHolders) {
		++numberOfTimesAddLookupsWasCalled;
		if (hmacHolders != null) {
			lookups = List.copyOf(hmacHolders);
		} else {
			lookups = null;
		}
	}

	@Override
	public void setUniqueValues(Collection<CryptoShieldHmacHolder> hmacHolders) {
		++numberOfTimesAddUniqueValuesWasCalled;
		if (hmacHolders != null) {
			uniqueValues = List.copyOf(hmacHolders);
		} else {
			uniqueValues = null;
		}
	}

	public List<CryptoShieldHmacHolder> getLookups() {
		return lookups;
	}

	public List<CryptoShieldHmacHolder> getUniqueValues() {
		return uniqueValues;
	}

	public int getNumberOfTimesAddLookupsWasCalled() {
		return numberOfTimesAddLookupsWasCalled;
	}

	public int getNumberOfTimesAddUniqueValuesWasCalled() {
		return numberOfTimesAddUniqueValuesWasCalled;
	}

	public String getEncryptionKeyId() {
		return encryptionKeyId;
	}

	public void setEncryptionKeyId(String encryptionKeyId) {
		this.encryptionKeyId = encryptionKeyId;
	}
}