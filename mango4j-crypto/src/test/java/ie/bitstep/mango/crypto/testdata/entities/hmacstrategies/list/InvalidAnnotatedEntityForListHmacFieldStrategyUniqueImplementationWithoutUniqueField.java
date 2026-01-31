package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.list;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.ListHmacStrategy;
import ie.bitstep.mango.crypto.domain.CryptoShieldHmacHolder;
import ie.bitstep.mango.crypto.domain.Lookup;
import ie.bitstep.mango.crypto.domain.Unique;

import java.util.Collection;
import java.util.List;

@ListHmacStrategy
public class InvalidAnnotatedEntityForListHmacFieldStrategyUniqueImplementationWithoutUniqueField implements Lookup, Unique {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	private transient String ethnicity;

	@EncryptedBlob
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

	}

	@Override
	public Collection<CryptoShieldHmacHolder> getLookups() {
		return List.of();
	}

	@Override
	public void setUniqueValues(Collection<CryptoShieldHmacHolder> hmacHolders) {

	}

	@Override
	public List<CryptoShieldHmacHolder> getUniqueValues() {
		return List.of();
	}
}