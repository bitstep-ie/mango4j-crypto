package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom;

import ie.bitstep.mango.crypto.annotations.EnableMigrationSupport;
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;

public class InvalidEntityWithEnableMigrationSupportAfterDeadline {

	@Encrypt
	@EnableMigrationSupport(
			completedBy = "2025-01-01",
			justification = "Test migration deadline passed"
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