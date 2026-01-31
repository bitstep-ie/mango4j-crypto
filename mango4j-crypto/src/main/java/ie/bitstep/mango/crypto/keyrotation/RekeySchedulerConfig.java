package ie.bitstep.mango.crypto.keyrotation;

import com.fasterxml.jackson.databind.ObjectMapper;
import ie.bitstep.mango.crypto.CryptoShield;
import ie.bitstep.mango.crypto.annotations.EncryptedBlob;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.encryption.EncryptionService;
import ie.bitstep.mango.crypto.core.providers.CryptoKeyProvider;
import ie.bitstep.mango.crypto.keyrotation.exceptions.RekeySchedulerInitializationException;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger.Level.ERROR;

public class RekeySchedulerConfig {
	private final Collection<RekeyService<?>> rekeyServices;
	private final ObjectMapper objectMapper;
	private final Clock clock;
	private final int initialDelay;
	private final Duration cryptoKeyCacheDuration;
	private Duration batchInterval = Duration.ZERO;
	private int maximumToleratedFailuresPerExecution = -1;
	private final RekeyCryptoKeyManager rekeyCryptoKeyManager;
	private final int rekeyCheckInterval;
	private final TimeUnit rekeyTimeUnits;
	private final CryptoShield cryptoShield;

	private RekeySchedulerConfig(Builder builder) {
		this.rekeyServices = builder.rekeyServices;
		this.objectMapper = builder.objectMapper;
		this.clock = builder.clock;
		this.initialDelay = builder.initialDelay;
		this.cryptoKeyCacheDuration = builder.cryptoKeyCacheDuration;
		this.batchInterval = builder.batchInterval;
		this.maximumToleratedFailuresPerExecution = builder.maximumToleratedFailuresPerExecution;
		this.rekeyCryptoKeyManager = builder.rekeyCryptoKeyManager;
		this.rekeyCheckInterval = builder.rekeyCheckInterval;
		this.rekeyTimeUnits = builder.rekeyTimeUnits;
		this.cryptoShield = builder.cryptoShield;
	}

	public static Builder builder() {
		return new Builder();
	}

	public Collection<RekeyService<?>> getRekeyServices() {
		return rekeyServices;
	}

	public ObjectMapper getObjectMapper() {
		return objectMapper;
	}

	public Clock getClock() {
		return clock;
	}

	public int getInitialDelay() {
		return initialDelay;
	}

	public Duration getCryptoKeyCacheDuration() {
		return cryptoKeyCacheDuration;
	}

	public Duration getBatchInterval() {
		return batchInterval;
	}

	public int getMaximumToleratedFailuresPerExecution() {
		return maximumToleratedFailuresPerExecution;
	}

	public RekeyCryptoKeyManager getRekeyCryptoKeyManager() {
		return rekeyCryptoKeyManager;
	}

	public int getRekeyCheckInterval() {
		return rekeyCheckInterval;
	}

	public TimeUnit getRekeyTimeUnits() {
		return rekeyTimeUnits;
	}

	public CryptoShield getCryptoShield() {
		return cryptoShield;
	}

	public static final class Builder {
		private static final System.Logger LOGGER = System.getLogger(Builder.class.getName());

		private Collection<RekeyService<?>> rekeyServices;
		private ObjectMapper objectMapper;
		private Clock clock;
		private int initialDelay;
		private Duration cryptoKeyCacheDuration;
		private Duration batchInterval = Duration.ZERO;
		private int maximumToleratedFailuresPerExecution = -1;
		private RekeyCryptoKeyManager rekeyCryptoKeyManager;
		private int rekeyCheckInterval;
		private TimeUnit rekeyTimeUnits;
		private CryptoShield cryptoShield;

		private Builder() {
		}

		/**
		 * Mandatory method. The usual {@link CryptoKeyProvider} implementation used by your application
		 *
		 * @return this
		 */
		public Builder withCryptoShield(CryptoShield cryptoShield) {
			this.cryptoShield = cryptoShield;
			return this;
		}

		/**
		 * Mandatory method: Sets all the application's {@link RekeyService} implementations that this scheduler will use to rekey records
		 *
		 * @param rekeyServices All {@link RekeyService} implementations for the application. There should be 1 {@link RekeyService}
		 *                      per entity that uses encryption.
		 * @return this
		 */
		public Builder withRekeyServices(Collection<RekeyService<?>> rekeyServices) {
			this.rekeyServices = rekeyServices;
			return this;
		}

		/**
		 * Mandatory method: Sets the {@link RekeyCryptoKeyManager} implementation that this scheduler will use to delete keys that are
		 * no longer in use.
		 *
		 * @param rekeyCryptoKeyManager {@link RekeyCryptoKeyManager} implementation for the application.
		 * @return this
		 */
		public Builder withRekeyCryptoKeyManager(RekeyCryptoKeyManager rekeyCryptoKeyManager) {
			this.rekeyCryptoKeyManager = rekeyCryptoKeyManager;
			return this;
		}

		/**
		 * Mandatory method: The {@link ObjectMapper} to use for generating the final ciphertext for
		 * &#64;{@link EncryptedBlob EncryptedBlob} fields.
		 * This should be the same as the one supplied to {@link CryptoShield}.
		 * We need it to be supplied here also because internally this class instantiates new {@link CryptoShield}
		 * instances for each rekey.
		 *
		 * @param objectMapper {@link ObjectMapper} implementation to use for
		 *                     &#64;{@link EncryptedBlob EncryptedBlob} ciphertext formatting
		 * @return this
		 */
		public Builder withObjectMapper(ObjectMapper objectMapper) {
			this.objectMapper = objectMapper;
			return this;
		}

		/**
		 * Mandatory method
		 *
		 * @param clock clock instance to use.
		 * @return this
		 */
		public Builder withClock(Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Mandatory method: This is an extremely important field to set and applications must make sure to set it to the correct value.
		 * Failure to set this to the correct value may have negative consequences for application functionality during a rekey job.
		 * If your application is multi-instance and caches {@link CryptoKey} data for performance reasons (very common) then
		 * there is a period of time after a new key is created in the system before all instances know about it. If a
		 * rekey job kicked off before this period then it would start to rekey encrypted data/HMACs to a key that some
		 * instances don't know about. In the case of HMACs this will result in search misses and possibly the more
		 * serious duplicate values problem (if HMACs are used to enforce uniqueness).
		 *
		 * @param cryptoKeyCacheDuration The length of time your application instances cache {@link CryptoKey CryptoKeys}
		 *                               for (if applicable). If not applicable then just set it to {@link Duration#ZERO}. Cannot be null.
		 * @return this
		 */
		public Builder withCryptoKeyCachePeriod(Duration cryptoKeyCacheDuration) {
			this.cryptoKeyCacheDuration = cryptoKeyCacheDuration;
			return this;
		}

		/**
		 * Optional method: To avoid overwhelming the application database and {@link EncryptionService}
		 * implementations, you can set this field to some duration. After each batch of records is re-keyed this library
		 * will sleep for this length of time before it asks {@link RekeyService#findRecordsNotUsingCryptoKey(CryptoKey)}
		 * or {@link RekeyService#findRecordsUsingCryptoKey(CryptoKey)} for another batch of records to rekey.
		 *
		 * @param batchInterval The amount of time to sleep after a batch of records is re-keyed.
		 * @return this
		 */
		public Builder withBatchInterval(Duration batchInterval) {
			this.batchInterval = batchInterval;
			return this;
		}

		/**
		 * Optional method: You can set a maximum value for failures for each rekey job that gets kicked off after which the
		 * job will abort. So if this class encounters some problems decrypting, re-encrypting or saving records then this job will abort
		 * this run of the process.
		 *
		 * @param maximumToleratedFailuresPerExecution The number of rekey failures that will trigger this library to abort
		 *                                             the rekey job (per tenant if applicable)
		 * @return this
		 */
		public Builder withMaximumToleratedFailuresPerExecution(int maximumToleratedFailuresPerExecution) {
			this.maximumToleratedFailuresPerExecution = maximumToleratedFailuresPerExecution;
			return this;
		}

		/**
		 * Mandatory method: This specifies the scheduling settings for this rekey Scheduler.
		 *
		 * @param initialDelay       The time after the {@link RekeyScheduler} instance is created which you want to wait before the first rekey job begins.
		 * @param rekeyCheckInterval The period of time between subsequent rekey jobs. Since rekey operations are usually
		 *                           quite rare setting this to once a day is probably adequate. This scheduler will wake up and check for any pending
		 *                           KEY_ON/KEY_OFF jobs (as signalled by the {@link CryptoKey#rekeyMode}) field.
		 * @param rekeyTimeUnits     The time units that initialDelay and rekeyCheckInterval parameters are specified in.
		 * @return this
		 */
		public Builder withRekeyCheckInterval(int initialDelay, int rekeyCheckInterval, TimeUnit rekeyTimeUnits) {
			this.initialDelay = initialDelay;
			this.rekeyCheckInterval = rekeyCheckInterval;
			this.rekeyTimeUnits = rekeyTimeUnits;
			return this;
		}

		public RekeySchedulerConfig build() {
			validateSettings();
			return new RekeySchedulerConfig(this);
		}

		private void validateSettings() {
			boolean isValid = areRekeyServicesValid()
					&& isCryptoShieldValid()
					&& isObjectMapperValid()
					&& isClockValid()
					&& isCryptoKeyCacheDurationValid()
					&& isRekeyCryptoManagerValid()
					&& isRekeyCheckIntervalValid()
					&& areRekeyTimeUnitsValid()
					&& isBatchIntervalValid();

			if (!isValid) {
				throw new RekeySchedulerInitializationException();
			}
		}

		private boolean isBatchIntervalValid() {
			if (batchInterval == null) {
				LOGGER.log(ERROR, "batchInterval field was set to null. Please make sure to set it to a non-null value using the withBatchInterval() method");
				return false;
			}
			return true;
		}

		private boolean areRekeyTimeUnitsValid() {
			if (rekeyTimeUnits == null) {
				LOGGER.log(ERROR, "rekeyTimeUnits field was set to null. Please make sure to set it to a non-null value using the withRekeyTimeUnits() method");
				return false;
			}
			return true;
		}

		private boolean isRekeyCheckIntervalValid() {
			if (rekeyCheckInterval <= 0) {
				LOGGER.log(ERROR, "rekeyCheckInterval field was set to {0}. Please make sure to set it to a positive non-zero integer value using the withRekeyCheckInterval() method", rekeyCheckInterval);
				return false;
			}
			return true;
		}

		private boolean isRekeyCryptoManagerValid() {
			if (rekeyCryptoKeyManager == null) {
				LOGGER.log(ERROR, "rekeyCryptoKeyManager field was set to a null value. Please make sure to set it to a non-null value using the withRekeyCryptoKeyManager() method");
				return false;
			}
			return true;
		}

		private boolean isCryptoKeyCacheDurationValid() {
			if (cryptoKeyCacheDuration == null) {
				LOGGER.log(ERROR, "cryptoKeyCacheDuration field was set to a null value. Please make sure to set it to a non-null value using the withCryptoKeyCachePeriod() method");
				return false;
			}
			return true;
		}

		private boolean isClockValid() {
			if (clock == null) {
				LOGGER.log(ERROR, "Clock field was set to a null value. Please make sure to set it to a non-null value using the withClock() method");
				return false;
			}
			return true;
		}

		private boolean isObjectMapperValid() {
			if (objectMapper == null) {
				LOGGER.log(ERROR, "ObjectMapper field was set to a null value. Please make sure to set it to a non-null value using the withObjectMapper() method");
				return false;
			}
			return true;
		}

		private boolean isCryptoShieldValid() {
			if (cryptoShield == null) {
				LOGGER.log(ERROR, "CryptoShield field was set to a null value. Please make sure to set it to a non-null value using the withCryptoShield() method");
				return false;
			}
			return true;
		}

		private boolean areRekeyServicesValid() {
			if (rekeyServices == null || rekeyServices.isEmpty()) {
				LOGGER.log(ERROR, "RekeyServices field was not set or is empty. Please make sure to set it to a non-empty collection using the withRekeyServices() method");
				return false;
			}
			return true;
		}
	}
}