package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.core.domain.CryptoKey;

import java.util.List;

public class RekeyEvent {
	Type type;
	Class<?> rekeyServiceClass;
	List<CryptoKey> cryptoKeysThatTriggeredTheRekey;
	ProgressTracker progressTracker;

	public Type getType() {
		return type;
	}

	public void setType(Type type) {
		this.type = type;
	}

	public Class<?> getRekeyServiceClass() {
		return rekeyServiceClass;
	}

	public void setRekeyServiceClass(Class<?> rekeyServiceClass) {
		this.rekeyServiceClass = rekeyServiceClass;
	}

	public List<CryptoKey> getCryptoKeysThatTriggeredTheRekey() {
		return cryptoKeysThatTriggeredTheRekey;
	}

	public void setCryptoKeysThatTriggeredTheRekey(List<CryptoKey> cryptoKeysThatTriggeredTheRekey) {
		this.cryptoKeysThatTriggeredTheRekey = cryptoKeysThatTriggeredTheRekey;
	}

	public ProgressTracker getProgressTracker() {
		return progressTracker;
	}

	public void setProgressTracker(ProgressTracker progressTracker) {
		this.progressTracker = progressTracker;
	}

	public enum Type {
		BATCH_REKEY_START,
		BATCH_REKEY_END,
		REKEY_FINISHED,
		PURGE_REDUNDANT_HMACS_ASSOCIATED_WITH_KEY
	}
}