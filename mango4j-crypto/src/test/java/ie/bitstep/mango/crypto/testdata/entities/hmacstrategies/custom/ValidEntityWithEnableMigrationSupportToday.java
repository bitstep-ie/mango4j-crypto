package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.custom;

import ie.bitstep.mango.crypto.annotations.EnableMigrationSupport;
import ie.bitstep.mango.crypto.annotations.Encrypt;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;

public class ValidEntityWithEnableMigrationSupportToday {

	@Encrypt
	@EnableMigrationSupport(
			completedBy = "2026-01-12",
			justification = "Test migration deadline is today"
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