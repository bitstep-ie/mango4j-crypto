package ie.bitstep.mango.crypto.testdata.entities.multipleciphergroups;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedData;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;

public class TestAnnotatedEntityForMultipleCipherGroups {

	public static final String HIGH_CONFIDENTIALITY_KEY_SELECTOR = "highConfidentialityKeySelector";
	public static final String LOW_CONFIDENTIALITY_KEY_SELECTOR = "lowConfidentialityKeySelector";
	public static final String HIGH_CONFIDENTIALITY_CIPHER_GROUP_NAME = "highConfidentiality";
	public static final String LOW_CONFIDENTIALITY_CIPHER_GROUP_NAME = "lowConfidentiality";
	public static final String HIGH_CONFIDENTIALITY_ENCRYPTED_DATA_FIELD_NAME = "highConfidentialityEncryptedData";
	public static final String LOW_CONFIDENTIALITY_ENCRYPTED_DATA_FIELD_NAME = "lowConfidentialityEncryptedData";
	public static final String HIGH_CONFIDENTIALITY_ENCRYPTION_KEY_ID_FIELD_NAME = "highConfidentialityEncryptionKeyId";
	public static final String LOW_CONFIDENTIALITY_ENCRYPTION_KEY_ID_FIELD_NAME = "lowConfidentialityEncryptionKeyId";

	@Encrypt(cipherGroup = HIGH_CONFIDENTIALITY_CIPHER_GROUP_NAME)
	private transient String pan;

	@Encrypt(cipherGroup = LOW_CONFIDENTIALITY_CIPHER_GROUP_NAME)
	private transient String userName;

	@EncryptedData(cipherGroup = HIGH_CONFIDENTIALITY_CIPHER_GROUP_NAME, keySelector = HIGH_CONFIDENTIALITY_KEY_SELECTOR)
	private String highConfidentialityEncryptedData;

	@EncryptedData(cipherGroup = LOW_CONFIDENTIALITY_CIPHER_GROUP_NAME, keySelector = LOW_CONFIDENTIALITY_KEY_SELECTOR)
	private String lowConfidentialityEncryptedData;

	private String favouriteColor;

	@EncryptionKeyId(cipherGroup = HIGH_CONFIDENTIALITY_CIPHER_GROUP_NAME)
	private String highConfidentialityEncryptionKeyId;

	@EncryptionKeyId(cipherGroup = LOW_CONFIDENTIALITY_CIPHER_GROUP_NAME)
	private String lowConfidentialityEncryptionKeyId;

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

	public String getHighConfidentialityEncryptionKeyId() {
		return highConfidentialityEncryptionKeyId;
	}

	public void setHighConfidentialityEncryptionKeyId(String highConfidentialityEncryptionKeyId) {
		this.highConfidentialityEncryptionKeyId = highConfidentialityEncryptionKeyId;
	}

	public String getLowConfidentialityEncryptionKeyId() {
		return lowConfidentialityEncryptionKeyId;
	}

	public void setLowConfidentialityEncryptionKeyId(String lowConfidentialityEncryptionKeyId) {
		this.lowConfidentialityEncryptionKeyId = lowConfidentialityEncryptionKeyId;
	}
}