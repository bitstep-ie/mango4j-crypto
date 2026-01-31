package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;

public class InvalidAnnotatedEntityNonTransientEncryptField {

	@Encrypt
	private String ethnicity;

	private String favouriteColor;


	@EncryptedBlob
	private String encryptedData;

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
}