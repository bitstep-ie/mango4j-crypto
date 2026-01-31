package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom;

public class NothingAnnotatedEntity {

	private transient String pan;

	private transient String userName;

	private transient String ethnicity;

	private String encryptedData;

	private String favouriteColor;

	private String userNameHmac1;

	private String userNameHmac2;

	private String panHmac1;

	private String panHmac2;

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
}