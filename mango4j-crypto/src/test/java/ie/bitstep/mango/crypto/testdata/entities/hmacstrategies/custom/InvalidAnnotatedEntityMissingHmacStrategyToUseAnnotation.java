package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.testdata.annotations.InvalidMissingHmacStrategyToUse;

@InvalidMissingHmacStrategyToUse
public class InvalidAnnotatedEntityMissingHmacStrategyToUseAnnotation {

	@Encrypt
	@Hmac
	private transient String pan;

	@Encrypt
	@Hmac
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	@EncryptedBlob
	private String encryptedData;

	private String favouriteColor;

	private String userNameHmac;

	private String panHmac;

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

	public String getUserNameHmac() {
		return userNameHmac;
	}

	public void setUserNameHmac(String userNameHmac) {
		this.userNameHmac = userNameHmac;
	}

	public String getPanHmac() {
		return panHmac;
	}

	public void setPanHmac(String panHmac) {
		this.panHmac = panHmac;
	}
}