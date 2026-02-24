package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.ListHmacStrategy;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;

import java.util.Collection;
import java.util.List;

@ListHmacStrategy
public class InvalidAnnotatedEntityForListHmacFieldStrategyUniqueFieldWithoutUniqueImplementation implements Lookup {

	@Encrypt
	@Hmac(purposes = {Hmac.Purposes.LOOKUP, Hmac.Purposes.UNIQUE})
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
	public void setLookups(Collection<CryptoShieldHmacHolder> hmacHolder) {
		// Only used for test validation, so can be left empty
	}

	@Override
	public List<CryptoShieldHmacHolder> getLookups() {
		return List.of();
	}
}