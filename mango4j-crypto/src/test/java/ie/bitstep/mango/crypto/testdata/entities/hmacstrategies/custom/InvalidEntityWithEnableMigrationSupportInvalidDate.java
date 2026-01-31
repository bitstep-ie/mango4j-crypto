package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom;

import ie.bitstep.mango.crypto.annotations.EnableMigrationSupport;
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;

public class InvalidEntityWithEnableMigrationSupportInvalidDate {

	@Encrypt
	@EnableMigrationSupport(
			completedBy = "invalid-date",
			justification = "Test invalid date format"
	)
	private String email;

	@EncryptedBlob
	private String encryptedData;

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}
}
