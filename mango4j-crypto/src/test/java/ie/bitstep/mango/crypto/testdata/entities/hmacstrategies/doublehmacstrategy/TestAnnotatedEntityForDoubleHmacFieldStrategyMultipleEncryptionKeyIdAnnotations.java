package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy;

import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.DoubleHmacStrategy;

@DoubleHmacStrategy
public class TestAnnotatedEntityForDoubleHmacFieldStrategyMultipleEncryptionKeyIdAnnotations {

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

	private String userNameHmac1;

	private String userNameHmac2;

	private String panHmac1;

	private String panHmac2;

	@EncryptionKeyId
	private String encryptionKeyId1;

	@EncryptionKeyId
	private String encryptionKeyId2;

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

	public String getUserNameHmac1() {
		return userNameHmac1;
	}

	public void setUserNameHmac1(String userNameHmac1) {
		this.userNameHmac1 = userNameHmac1;
	}

	public String getUserNameHmac2() {
		return userNameHmac2;
	}

	public void setUserNameHmac2(String userNameHmac2) {
		this.userNameHmac2 = userNameHmac2;
	}

	public String getPanHmac1() {
		return panHmac1;
	}

	public void setPanHmac1(String panHmac1) {
		this.panHmac1 = panHmac1;
	}

	public String getPanHmac2() {
		return panHmac2;
	}

	public void setPanHmac2(String panHmac2) {
		this.panHmac2 = panHmac2;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	public String getEncryptionKeyId1() {
		return encryptionKeyId1;
	}

	public void setEncryptionKeyId1(String encryptionKeyId1) {
		this.encryptionKeyId1 = encryptionKeyId1;
	}

	public String getEncryptionKeyId2() {
		return encryptionKeyId2;
	}

	public void setEncryptionKeyId2(String encryptionKeyId2) {
		this.encryptionKeyId2 = encryptionKeyId2;
	}
}