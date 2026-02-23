package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.ListHmacStrategy;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;
import ie.bitstep.mango.crypto.domain.Unique;

import java.util.Collection;
import java.util.List;

@ListHmacStrategy
public class InvalidAnnotatedEntityForListHmacFieldStrategyLookupImplementationWithoutLookupField implements Lookup, Unique {

	@Encrypt
	@Hmac(purposes = Hmac.Purposes.UNIQUE)
	private transient String pan;

	@Encrypt
	private transient String ethnicity;

	@EncryptedData
	private String encryptedData;

	private String favouriteColor;

	public String getPan() {
		return pan;
	}

	public void setPan(String pan) {
		this.pan = pan;
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
		// Only used for testing purposes, not a valid implementation as this entity is only intended to be used for
		// testing the ListHmacStrategy when it implements Lookup but does not have a field annotated with @Hmac that
		// has the Lookup purpose, this method is not relevant for this test
	}

	@Override
	public Collection<CryptoShieldHmacHolder> getLookups() {
		return List.of();
	}

	@Override
	public void setUniqueValues(Collection<CryptoShieldHmacHolder> hmacHolders) {
		// Only used for testing purposes, not a valid implementation as this entity is only intended to be used for
		// testing the ListHmacStrategy when it implements Lookup but does not have a field annotated with @Hmac that
		// has the Lookup purpose, this method is not relevant for this test
	}

	@Override
	public List<CryptoShieldHmacHolder> getUniqueValues() {
		return List.of();
	}
}