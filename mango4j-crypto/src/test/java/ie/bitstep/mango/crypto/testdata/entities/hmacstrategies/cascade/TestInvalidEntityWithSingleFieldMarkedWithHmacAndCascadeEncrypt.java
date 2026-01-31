package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.cascade;

import ie.bitstep.mango.crypto.annotations.CascadeEncrypt;
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;
import ie.bitstep.mango.crypto.annotations.EncryptionKeyId;
import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.strategies.HmacStrategyToUse;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.HighlyConfidentialObject;
import ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.TestMockHmacEntity;
import ie.bitstep.mango.crypto.testdata.implementations.hmacstrategies.MockHmacStrategyImpl;

@HmacStrategyToUse(MockHmacStrategyImpl.class)
public class TestInvalidEntityWithSingleFieldMarkedWithHmacAndCascadeEncrypt {

	@Hmac
	@CascadeEncrypt
	private transient String pan;

	@Encrypt
	@Hmac(purposes = {Hmac.Purposes.LOOKUP, Hmac.Purposes.UNIQUE})
	private transient String userName;

	@Encrypt
	private transient String ethnicity;

	@Encrypt
	private transient HighlyConfidentialObject highlyConfidentialObject;

	@CascadeEncrypt
	private TestMockHmacEntity testMockHmacEntity1;

	@CascadeEncrypt
	private TestMockHmacEntity testMockHmacEntity2;

	private TestMockHmacEntity testMockHmacEntity3NotTraversed;

	private String favouriteColor;

	@EncryptedBlob
	private String encryptedData;

	@EncryptionKeyId
	private String encryptionKeyId;

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

	public String getEncryptedData() {
		return encryptedData;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getEncryptionKeyId() {
		return encryptionKeyId;
	}

	public void setEncryptionKeyId(String encryptionKeyId) {
		this.encryptionKeyId = encryptionKeyId;
	}

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}

	public HighlyConfidentialObject getHighlyConfidentialObject() {
		return highlyConfidentialObject;
	}

	public void setHighlyConfidentialObject(HighlyConfidentialObject highlyConfidentialObject) {
		this.highlyConfidentialObject = highlyConfidentialObject;
	}
}