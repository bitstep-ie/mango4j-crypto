package ie.bitstep.mango.crypto.testdata.entities.multipleciphergroups;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;

public class TestAnnotatedEntityForMultipleCipherGroupsOneGroupHasNoMatchingEncryptionKeyId {

	@Encrypt(cipherGroup = "highConfidentiality")
	private transient String pan;

	@Encrypt(cipherGroup = "lowConfidentiality")
	private transient String userName;

	@EncryptedData(cipherGroup = "highConfidentiality")
	private String highConfidentialityEncryptedData;

	@EncryptedData(cipherGroup = "lowConfidentiality")
	private String lowConfidentialityEncryptedData;

	private String favouriteColor;

	@EncryptionKeyId(cipherGroup = "highConfidentiality")
	private String highConfidentialityEncryptionKeyId;

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

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}

	public String getLowConfidentialityEncryptedData() {
		return lowConfidentialityEncryptedData;
	}

	public void setLowConfidentialityEncryptedData(String lowConfidentialityEncryptedData) {
		this.lowConfidentialityEncryptedData = lowConfidentialityEncryptedData;
	}

	public void setHighConfidentialityEncryptedData(String highConfidentialityEncryptedData) {
		this.highConfidentialityEncryptedData = highConfidentialityEncryptedData;
	}

	public String getHighConfidentialityEncryptedData() {
		return highConfidentialityEncryptedData;
	}
}