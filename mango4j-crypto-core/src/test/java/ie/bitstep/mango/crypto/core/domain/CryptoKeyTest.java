package ie.bitstep.mango.crypto.core.domain;

import ie.bitstep.mango.crypto.core.enums.TestCryptoKeyTypes;
import ie.bitstep.mango.crypto.core.testdata.TestData;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoKeyTest {

	private static final String TEST_ID = "TEST_ID";
	private static final Map<String, Object> TEST_KEY_CONFIGURATION = Map.of();
	private static final Instant TEST_KEY_CREATED_DATE = Instant.ofEpochSecond(100000000);
	private static final Instant TEST_KEY_START_TIME = Instant.ofEpochSecond(100000100);
	private static final String TEST_TENANT_ID = "TestTenantId";

	@Test
	void constructor() {
		CryptoKey cryptoKey = new CryptoKey();

		assertThat(cryptoKey.getId()).isNull();
		assertThat(cryptoKey.getType()).isNull();
		assertThat(cryptoKey.getUsage()).isNull();
		assertThat(cryptoKey.getConfiguration()).isNull();
		assertThat(cryptoKey.getTenantId()).isNull();
		assertThat(cryptoKey.getCreatedDate()).isNull();
		assertThat(cryptoKey.getKeyStartTime()).isNull();
		assertThat(cryptoKey.getRekeyMode()).isNull();
	}

	@Test
	void setters() {
		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setId(TEST_ID);
		cryptoKey.setType(TestCryptoKeyTypes.TEST.getName());
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setConfiguration(TEST_KEY_CONFIGURATION);
		cryptoKey.setKeyStartTime(TEST_KEY_START_TIME);
		cryptoKey.setTenantId(TEST_TENANT_ID);
		cryptoKey.setCreatedDate(TEST_KEY_CREATED_DATE);
		cryptoKey.setRekeyMode(CryptoKey.RekeyMode.KEY_ON);

		assertThat(cryptoKey.getId()).isEqualTo(TEST_ID);
		assertThat(cryptoKey.getType()).isEqualTo(TestCryptoKeyTypes.TEST.getName());
		assertThat(cryptoKey.getUsage()).isEqualTo(CryptoKeyUsage.ENCRYPTION);
		assertThat(cryptoKey.getConfiguration()).isEqualTo(TEST_KEY_CONFIGURATION);
		assertThat(cryptoKey.getKeyStartTime()).isEqualTo(TEST_KEY_START_TIME);
		assertThat(cryptoKey.getTenantId()).isEqualTo(TEST_TENANT_ID);
		assertThat(cryptoKey.getCreatedDate()).isEqualTo(TEST_KEY_CREATED_DATE);
		assertThat(cryptoKey.getRekeyMode()).isEqualTo(CryptoKey.RekeyMode.KEY_ON);
	}

	@Test
	void hashCodeTest() {
		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setId(TestData.TEST_CRYPTO_KEY_ID);

		assertThat(cryptoKey.hashCode()).isEqualTo(274565100);
	}

	@SuppressWarnings("EqualsWithItself")
	@Test
	void equalsTestSameObject() {
		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setId(TestData.TEST_CRYPTO_KEY_ID);
		cryptoKey.setRekeyMode(CryptoKey.RekeyMode.KEY_ON);

		assertThat(cryptoKey.equals(cryptoKey)).isTrue();
	}

	@Test
	void equalsWithDifferentObject() {
		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setId(TestData.TEST_CRYPTO_KEY_ID);

		CryptoKey subclass = new CryptoKey() {
		};
		subclass.setId(TestData.TEST_CRYPTO_KEY_ID);

		assertThat(cryptoKey.equals(subclass)).isFalse();
	}

	@Test
	void equalsTestSameIdButDifferentRekeyModes() {
		CryptoKey cryptoKey1 = new CryptoKey();
		cryptoKey1.setId(TestData.TEST_CRYPTO_KEY_ID);
		cryptoKey1.setRekeyMode(CryptoKey.RekeyMode.KEY_ON);

		CryptoKey cryptoKey2 = new CryptoKey();
		cryptoKey2.setId(TestData.TEST_CRYPTO_KEY_ID);
		cryptoKey2.setRekeyMode(CryptoKey.RekeyMode.KEY_OFF);

		assertThat(cryptoKey1.equals(cryptoKey2)).isTrue();
	}

	@Test
	void equalsTestDifferentIds() {
		CryptoKey cryptoKey1 = new CryptoKey();
		cryptoKey1.setId(TestData.TEST_CRYPTO_KEY_ID);

		CryptoKey cryptoKey2 = new CryptoKey();
		cryptoKey2.setId("Some Other Crypto Key ID");

		assertThat(cryptoKey1.equals(cryptoKey2)).isFalse();
	}

	@SuppressWarnings("ConstantValue")
	@Test
	void equalsNullOther() {
		CryptoKey cryptoKey1 = new CryptoKey();
		cryptoKey1.setId(TestData.TEST_CRYPTO_KEY_ID);

		assertThat(cryptoKey1.equals(null)).isFalse();
	}

	@Test
	void toStringTest() {
		CryptoKey cryptoKey = new CryptoKey();
		cryptoKey.setId(TEST_ID);
		cryptoKey.setType(TestCryptoKeyTypes.TEST.getName());
		cryptoKey.setUsage(CryptoKeyUsage.ENCRYPTION);
		cryptoKey.setConfiguration(TEST_KEY_CONFIGURATION);
		cryptoKey.setKeyStartTime(TEST_KEY_START_TIME);
		cryptoKey.setTenantId(TEST_TENANT_ID);
		cryptoKey.setCreatedDate(TEST_KEY_CREATED_DATE);
		cryptoKey.setRekeyMode(CryptoKey.RekeyMode.KEY_ON);

		assertThat(cryptoKey.toString()).hasToString("CryptoKey{id='TEST_ID', type=TEST, usage=ENCRYPTION, keyStartTime=1973-03-03T09:48:20Z, tenantId='TestTenantId', rekeyMode=KEY_ON, createdDate=1973-03-03T09:46:40Z}");
	}
}