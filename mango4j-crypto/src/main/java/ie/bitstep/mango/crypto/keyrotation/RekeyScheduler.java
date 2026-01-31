package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.RekeyCryptoShield;
import ie.bitstep.mango.crypto.core.domain.CryptoKey;
import ie.bitstep.mango.crypto.core.domain.CryptoKeyUsage;
import ie.bitstep.mango.crypto.keyrotation.exceptions.TooManyFailuresException;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode.KEY_OFF;
import static ie.bitstep.mango.crypto.core.domain.CryptoKey.RekeyMode.KEY_ON;
import static ie.bitstep.mango.crypto.keyrotation.RekeyEvent.Type.REKEY_FINISHED;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.ERROR;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.TRACE;
import static java.lang.System.Logger.Level.WARNING;

/**
 * <b>Warning!!!</b> This class is currently experimental and is expected to go through several more iterations of both redesign
 * and refactoring. If you can read this message, don't use in production code just yet.
 */
@SuppressWarnings("unused")
public class RekeyScheduler {
	private static final String[] ORDINAL_SUFFIXES = new String[]{"th", "st", "nd", "rd", "th", "th", "th", "th", "th", "th"};

	private final System.Logger logger = System.getLogger(RekeyScheduler.class.getName());
	private final RekeySchedulerConfig rekeySchedulerConfig;

	public RekeyScheduler(RekeySchedulerConfig rekeySchedulerConfig) {
		this.rekeySchedulerConfig = rekeySchedulerConfig;
		ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
		scheduler.scheduleAtFixedRate(this::rekeyTenants, this.rekeySchedulerConfig.getInitialDelay(), this.rekeySchedulerConfig.getRekeyCheckInterval(), this.rekeySchedulerConfig.getRekeyTimeUnits());
	}

	private void rekeyTenants() {
		logger.log(TRACE, "Beginning rekey job");
		Map<String, List<CryptoKey>> allEncryptionKeys = new HashMap<>();
		for (CryptoKey cryptoKey : rekeySchedulerConfig.getCryptoShield().getCryptoKeyProvider().getAllCryptoKeys()) {
			// HashMap allows null keys so if the app doesn't have tenants then cryptokey.getTenantId() can return null and
			// this functionality will still work fine
			allEncryptionKeys.computeIfAbsent(cryptoKey.getTenantId(), tenantId -> new ArrayList<>()).add(cryptoKey);
		}
		if (allEncryptionKeys.isEmpty()) {
			logger.log(TRACE, "No keys found to rekey");
		}

		for (Map.Entry<String, List<CryptoKey>> tenantsCryptoKeysEntry : allEncryptionKeys.entrySet()) {
			try {
				rekeyTenant(tenantsCryptoKeysEntry.getKey(), tenantsCryptoKeysEntry.getValue());
			} catch (TooManyFailuresException e) {
				logger.log(ERROR, "Too many failures occurred trying to rekey records", e);
			}
		}
	}

	private void rekeyTenant(String tenantId, List<CryptoKey> tenantCryptoKeys) {
		if (tenantCryptoKeys.size() <= 1) {
			logger.log(ERROR, "There are no Crypto Keys defined{0}", tenantLogString(tenantId));
			return;
		}

		if (tenantCryptoKeys.stream().anyMatch(cryptoKey -> cryptoKey.getCreatedDate() == null)) {
			logger.log(ERROR, "Created date was not set to a valid value on some Crypto Keys{0}.....skipping rekey for this tenant", tenantLogString(tenantId));
			return;
		}

		List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending = tenantCryptoKeys.stream()
				.sorted(Comparator.comparing(CryptoKey::getCreatedDate).reversed())
				.toList();

		// TODO: Currently we re-encrypt and re-HMAC separately which isn't very performant. Once this automated rekey code is
		// settled and out of beta we need to come back and make that these are done together, especially for entities that have both
		// encrypted data and HMACs
		try {
			reEncrypt(tenantId, tenantAllCryptoKeysSortedByDateDescending);
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to rekey encryption keys{0}", tenantLogString(tenantId));
		}

		try {
			reHmac(tenantId, tenantAllCryptoKeysSortedByDateDescending);
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to rekey HMAC keys{0}", tenantLogString(tenantId));
		}
	}

	private void reEncrypt(String tenantId, List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending) {
		logger.log(TRACE, "Beginning re-encrypt for tenant {0}", tenantId);
		List<CryptoKey> tenantEncryptionKeysSortedByDateDescending = tenantAllCryptoKeysSortedByDateDescending.stream()
				.filter(cryptoKey -> cryptoKey.getUsage() == CryptoKeyUsage.ENCRYPTION)
				.toList();
		CryptoKey tenantLatestEncryptionKey = tenantEncryptionKeysSortedByDateDescending.stream()
				.findFirst()
				.orElse(null);
		if (tenantLatestEncryptionKey == null) {
			logger.log(INFO, "No encryption key was found{0}.....skipping the currently scheduled encryption rekey tasks for this tenant ", tenantLogString(tenantId));
			return;
		} else if (tenantLatestEncryptionKey.getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now())) {
			logger.log(DEBUG, "Some application instances might not be using the new encryption key yet{0}.....skipping the currently scheduled encryption rekey task for this tenant", tenantLogString(tenantId));
			return;
		}

		if (tenantLatestEncryptionKey.getRekeyMode() == KEY_ON) {
			logger.log(TRACE, "RekeyMode is set to {0} on the latest encryption key{1}", KEY_ON, tenantLogString(tenantId));
			if (doAnyEncryptedRecordsNeedRekeying(keyOnRecordSupplier(tenantLatestEncryptionKey))) {
				logger.log(TRACE, "Some records need re-encrypted{0}", tenantLogString(tenantId));
				RekeyCryptoShield rekeyCryptoShield = new RekeyCryptoShield(rekeySchedulerConfig.getCryptoShield(), tenantLatestEncryptionKey, null);
				long totalEncryptedRecordsRekeyedForTenant = rekey(tenantLatestEncryptionKey, rekeyCryptoShield, keyOnRecordSupplier(tenantLatestEncryptionKey));
				logger.log(INFO, "Full re-key of all records has been completed{0}. Total of {1} records rekeyed to {2} by this job", tenantLogString(tenantId), totalEncryptedRecordsRekeyedForTenant, tenantLatestEncryptionKey);
			} else {
				logger.log(TRACE, "No records need re-encrypted{0}", tenantLogString(tenantId));
			}
			removeUnusedEncryptionKeys(tenantEncryptionKeysSortedByDateDescending);
		} else if (tenantEncryptionKeysSortedByDateDescending.stream().anyMatch(cryptoKey -> cryptoKey.getRekeyMode() == KEY_OFF)) {
			logger.log(TRACE, "RekeyMode is set to {0} on {2} encryption keys{1}", KEY_OFF, tenantLogString(tenantId), tenantEncryptionKeysSortedByDateDescending.stream().filter(cryptoKey -> cryptoKey.getRekeyMode() == KEY_OFF).count());
			if (tenantLatestEncryptionKey.getRekeyMode() == KEY_OFF) {
				logger.log(ERROR, "RekeyMode is set to {0} on the latest encryption key{1}. This is a misconfiguration, the latest encryption key should not be set to KEY_OFF!!.....skipping the currently scheduled encryption rekey task for this tenant", KEY_OFF, tenantLogString(tenantId));
				return;
			}
			for (CryptoKey encryptionKey : tenantEncryptionKeysSortedByDateDescending.subList(1, tenantEncryptionKeysSortedByDateDescending.size())) {
				if (encryptionKey.getRekeyMode() == KEY_OFF && encryptionKey.getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isBefore(now())) {
					logger.log(TRACE, "Checking if there are any records using {0} to rekey", encryptionKey);
					if (doAnyEncryptedRecordsNeedRekeying(keyOffRecordSupplier(encryptionKey))) {
						logger.log(TRACE, "Some records need rekeyed{0}", tenantLogString(tenantId));
						RekeyCryptoShield rekeyCryptoShield = new RekeyCryptoShield(rekeySchedulerConfig.getCryptoShield(), tenantLatestEncryptionKey, null);
						long totalEncryptedRecordsRekeyedForTenant = rekey(tenantLatestEncryptionKey, rekeyCryptoShield, keyOffRecordSupplier(encryptionKey));
						logger.log(INFO, "All records ({0}) using deprecated encryption key {1} have been keyed onto the current encryption key {2}",
								totalEncryptedRecordsRekeyedForTenant, encryptionKey, tenantLatestEncryptionKey);
					} else {
						logger.log(TRACE, "No records need keyed off {0}", encryptionKey);
					}
					logger.log(DEBUG, "No application instances are using the following deprecated encryption key anymore (and any records which previously used it have been re-keyed to the latest encryption key), so we''ll delete it: {0}", encryptionKey);
					removeKey(encryptionKey);
				}
			}
		} else {
			logger.log(TRACE, "No Re-keying needed{0}", tenantLogString(tenantId));
		}
	}

	private static String tenantLogString(String tenantId) {
		return tenantId == null ? "" : " for tenant " + tenantId;
	}

	/**
	 * There's only ever 1 active encryption key at one time, so we can delete any keys that aren't that key
	 *
	 * @param tenantEncryptionKeysSortedByDateDescending All of a tenants encryption keys in order of latest to oldest
	 */
	private void removeUnusedEncryptionKeys(List<CryptoKey> tenantEncryptionKeysSortedByDateDescending) {
		String tenantId = tenantEncryptionKeysSortedByDateDescending.get(0).getTenantId();
		logger.log(TRACE, "Attempting to remove any deprecated encryption keys{0}", tenantLogString(tenantId));
		if (tenantEncryptionKeysSortedByDateDescending.size() > 1) {
			// only remove the older keys, the first key in the list is the latest key (so don't touch that)
			tenantEncryptionKeysSortedByDateDescending.subList(1, tenantEncryptionKeysSortedByDateDescending.size()).clear();
			for (CryptoKey tenantEncryptionKey : tenantEncryptionKeysSortedByDateDescending.subList(1, tenantEncryptionKeysSortedByDateDescending.size())) {
				logger.log(DEBUG, "All application instances are now using only the latest encryption key{0} and are no longer using the following encryption key so we''ll mark it for deletion: {1}", tenantLogString(tenantId), tenantEncryptionKey);
				removeKey(tenantEncryptionKey);
			}
		} else {
			logger.log(DEBUG, "{0} only has a single encryption key, there''s no old encryption keys to delete", tenantLogString(tenantId));
		}
	}

	private void reHmac(String tenantId, List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending) {
		Optional<CryptoKey> hmacKeyToRekeyTo = getHmacKeyToRekeyTo(tenantAllCryptoKeysSortedByDateDescending);
		if (hmacKeyToRekeyTo.isEmpty()) {
			logger.log(ERROR, "No valid HMAC key found to rekey to{0}.....skipping HMAC rekey for this tenant", tenantLogString(tenantId));
			return;
		} else if (hmacKeyToRekeyTo.get().getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now())) {
			logger.log(DEBUG, "Some application instances might not be using some of the HMAC keys yet{0}....." +
							"skipping the currently scheduled HMAC rekey tasks{0}",
					tenantLogString(tenantId));
			return;
		}

		List<CryptoKey> tenantHmacKeysSortedByDateDescending = getTenantHmacKeysSortedByDateDescending(tenantAllCryptoKeysSortedByDateDescending);
		if (tenantHmacKeysSortedByDateDescending.isEmpty()) {
			logger.log(INFO, "No HMACs to rekey{0}", tenantLogString(tenantId));
			return;
		} else if (hmacKeyToRekeyTo.get().getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now())) {
			logger.log(DEBUG, "Some application instances might not be using some of the HMAC keys yet{0}....." +
							"skipping the currently scheduled HMAC rekey tasks{0}",
					tenantLogString(tenantId));
			return;
		}

		if (doAnyRecordsWithHmacsNeedRekeying(tenantHmacKeysSortedByDateDescending)) {
			if (tenantHmacKeysSortedByDateDescending.get(0).getRekeyMode() == KEY_ON) {
				RekeyCryptoShield rekeyCryptoShield = new RekeyCryptoShield(rekeySchedulerConfig.getCryptoShield(), null, hmacKeyToRekeyTo.get());
				long totalHmacRecordsRekeyedToTheCurrentKey = rekey(hmacKeyToRekeyTo.get(), rekeyCryptoShield, keyOnRecordSupplier(hmacKeyToRekeyTo.get()));
				logger.log(INFO, "Full HMAC re-key of all ({0}) records has been completed{1}", totalHmacRecordsRekeyedToTheCurrentKey, tenantLogString(tenantId));
				for (CryptoKey tenantHmacKey : tenantHmacKeysSortedByDateDescending) {
					if (canBeRemoved(tenantHmacKey)) {
						removeKey(tenantHmacKey);
					} else {
						logger.log(INFO, "The following HMAC key is not yet ready to be marked as deleted: {0}", tenantHmacKey);
					}
				}
			} else {
				// TODO: Update to find records which are using the KEY_OFF key but not all the keys after that
				tenantHmacKeysSortedByDateDescending.stream()
						.filter(hmacKey -> hmacKey.getRekeyMode() == KEY_OFF)
						.forEach(deprecatedHmacKey -> {
							RekeyCryptoShield rekeyCryptoShield = new RekeyCryptoShield(rekeySchedulerConfig.getCryptoShield(), null, hmacKeyToRekeyTo.get());
							long totalHmacRecordsRekeyedForThisKey = rekey(deprecatedHmacKey, rekeyCryptoShield, keyOffRecordSupplier(deprecatedHmacKey));
							logger.log(INFO, "HMAC re-key of all ({0}) records using deprecated HMAC key {1} has been completed{2}",
									totalHmacRecordsRekeyedForThisKey, deprecatedHmacKey, tenantLogString(tenantId));
							removeKey(deprecatedHmacKey);
						});
			}
		}
	}

	private boolean canBeRemoved(CryptoKey tenantHmacKey) {
		return tenantHmacKey.getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isBefore(now());
	}

	private boolean doAnyEncryptedRecordsNeedRekeying(Function<RekeyService<?>, List<?>> recordsNeedingRekeyedFunction) {
		List<?> recordsNeedingRekeyed;
		boolean doAnyRecordsNeedRekeying = false;
		for (RekeyService<?> rekeyService : rekeySchedulerConfig.getRekeyServices()) {
			try {
				recordsNeedingRekeyed = getRecords(rekeyService, recordsNeedingRekeyedFunction);
				if (recordsNeedingRekeyed != null && !recordsNeedingRekeyed.isEmpty()) {
					doAnyRecordsNeedRekeying = true;
					break;
				}
			} catch (Exception e) {
				logger.log(ERROR, "An error occurred trying to get records from RekeyService<{0}>", rekeyService.getEntityType());
			}
		}
		return doAnyRecordsNeedRekeying;
	}

	private boolean doAnyRecordsWithHmacsNeedRekeying(List<CryptoKey> tenantHmacKeys) {
		boolean doAnyRecordsNeedRekeying = false;
		for (CryptoKey tenantHmacKey : tenantHmacKeys) {
			if (doAnyRecordsNeedRekeying) {
				break;
			}

			Function<RekeyService<?>, List<?>> recordsNeedingRekeyedFunction = null;
			if (tenantHmacKey.getRekeyMode() == KEY_ON) {
				recordsNeedingRekeyedFunction = keyOnRecordSupplier(tenantHmacKey);
			} else if (tenantHmacKey.getRekeyMode() == KEY_OFF) {
				recordsNeedingRekeyedFunction = keyOffRecordSupplier(tenantHmacKey);
			}
			if (recordsNeedingRekeyedFunction != null) {
				for (RekeyService<?> rekeyService : rekeySchedulerConfig.getRekeyServices()) {
					List<?> recordsNeedingRekeyed = getRecords(rekeyService, recordsNeedingRekeyedFunction);
					if (recordsNeedingRekeyed != null && !recordsNeedingRekeyed.isEmpty()) {
						doAnyRecordsNeedRekeying = true;
						break;
					}
				}
			}
		}
		return doAnyRecordsNeedRekeying;
	}

	private List<?> getRecords(RekeyService<?> rekeyService, Function<RekeyService<?>, List<?>> recordsNeedingRekeyedFunction) {
		List<?> recordsNeedingRekeyed = null;
		try {
			recordsNeedingRekeyed = recordsNeedingRekeyedFunction.apply(rekeyService);
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to get records from RekeyService<{0}>", rekeyService.getEntityType());
		}
		return recordsNeedingRekeyed;
	}

	private Optional<CryptoKey> getHmacKeyToRekeyTo(List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending) {
		List<CryptoKey> tenantHmacKeysSortedByDateDescending = getTenantHmacKeysSortedByDateDescending(tenantAllCryptoKeysSortedByDateDescending);
		if (tenantHmacKeysSortedByDateDescending.isEmpty()) {
			logger.log(DEBUG, "No HMAC keys exist{0}", tenantLogString(tenantAllCryptoKeysSortedByDateDescending.get(0).getTenantId()));
			return Optional.empty();
		} else if (tenantHmacKeysSortedByDateDescending.stream().anyMatch(cryptoKey -> cryptoKey.getCreatedDate().plus(rekeySchedulerConfig.getCryptoKeyCacheDuration()).isAfter(now()))) {
			logger.log(DEBUG, "Some application instances might not be using some of the HMAC keys yet{0}....." +
							"so we''ll skip rekeying any HMACs{0}",
					tenantLogString(tenantHmacKeysSortedByDateDescending.get(0).getTenantId()));
			return Optional.empty();
		}

		Optional<CryptoKey> tenantHmacKeyToRekeyToMaybe = Optional.empty();

		if (tenantHmacKeysSortedByDateDescending.get(0).getRekeyMode() == KEY_ON) {
			// KEY_ON means rekey all HMACs to this key
			tenantHmacKeyToRekeyToMaybe = Optional.of(tenantHmacKeysSortedByDateDescending.get(0));
		} else if (tenantHmacKeysSortedByDateDescending.stream()
				.anyMatch(tenantHmacKey -> tenantHmacKey.getRekeyMode() == KEY_OFF)) {
			// if the oldest key is key off then we just need to key on to the next most recent key that is not KEY_OFF
			// if a KEY_OFF key is not the oldest key the just delete the key without a rekey
			int newestDeprecatedKeyFromStart = 0;
			for (int i = 0; i < tenantHmacKeysSortedByDateDescending.size(); i++) {
				if (i == newestDeprecatedKeyFromStart
						&& tenantHmacKeysSortedByDateDescending.get(i).getRekeyMode() == KEY_OFF) {
					++newestDeprecatedKeyFromStart;
					continue;
				}
				tenantHmacKeyToRekeyToMaybe = Optional.of(tenantHmacKeysSortedByDateDescending.get(newestDeprecatedKeyFromStart + 1));
			}
		}
		return tenantHmacKeyToRekeyToMaybe;
	}

	private static List<CryptoKey> getTenantHmacKeysSortedByDateDescending(List<CryptoKey> tenantAllCryptoKeysSortedByDateDescending) {
		return tenantAllCryptoKeysSortedByDateDescending.stream()
				.filter(cryptoKey -> cryptoKey.getUsage() == CryptoKeyUsage.HMAC)
				.toList();
	}

	private static Function<RekeyService<?>, List<?>> keyOnRecordSupplier(CryptoKey cryptoKey) {
		return (rekeyService) -> rekeyService.findRecordsNotUsingCryptoKey(cryptoKey);
	}

	private static Function<RekeyService<?>, List<?>> keyOffRecordSupplier(CryptoKey cryptoKey) {
		return (rekeyService) -> rekeyService.findRecordsUsingCryptoKey(cryptoKey);
	}

	@SuppressWarnings("BusyWait")
	private long rekey(CryptoKey keyThatTriggeredTheRekey, RekeyCryptoShield rekeyCryptoShield, Function<RekeyService<?>, List<?>> recordsSupplier) {
		logger.log(DEBUG, "Running re-key job. Keying {0} CryptoKey: {1}",
				keyThatTriggeredTheRekey.getRekeyMode() == KEY_OFF ? "off" : "on", keyThatTriggeredTheRekey);
		AtomicLong count = new AtomicLong();
		rekeySchedulerConfig.getRekeyServices().forEach((rekeyService) -> {
			logger.log(DEBUG, "Checking for records to re-key for entity {0}", rekeyService.getEntityType().getName());
			ProgressTracker entityRekeyProgressTracker = new ProgressTracker(rekeySchedulerConfig.getMaximumToleratedFailuresPerExecution());
			while (!rekeyBatch(rekeyService.getEntityType(), rekeyService, entityRekeyProgressTracker, rekeyCryptoShield, recordsSupplier)) {
				if (!Duration.ZERO.equals(rekeySchedulerConfig.getBatchInterval())) {
					try {
						logger.log(DEBUG, "Waiting for {0} milliseconds before re-keying another batch of records for entity {1}", rekeySchedulerConfig.getBatchInterval(), rekeyService.getEntityType().getName());
						Thread.sleep(rekeySchedulerConfig.getBatchInterval().toMillis());
					} catch (InterruptedException e) {
						logger.log(ERROR, String.format("An error occurred waiting to re-key the next batch of records for entity %s....cancelling this re-key task", rekeyService.getEntityType().getName()), e);
						Thread.currentThread().interrupt();
						return;
					}
				}
			}

			if (entityRekeyProgressTracker.getNumberOfRecordsProcessed() > 0) {
				logger.log(INFO, "Re-key complete for {0}.", rekeyService.getEntityType().getName());
				RekeyEvent rekeyFinishedEvent = new RekeyEvent();
				rekeyFinishedEvent.setRekeyServiceClass(rekeyService.getClass());
				rekeyFinishedEvent.setCryptoKey(keyThatTriggeredTheRekey);
				rekeyFinishedEvent.setType(REKEY_FINISHED);
				rekeyFinishedEvent.setProgressTracker(entityRekeyProgressTracker);
				rekeyService.notify(rekeyFinishedEvent);
			}
			count.addAndGet(entityRekeyProgressTracker.getNumberOfRecordsProcessed());
		});
		return count.get();
	}

	/**
	 * @return true if there were no records in this batch to process, meaning that we're finished re-keying this entity. False otherwise.
	 */
	private boolean rekeyBatch(Class<?> entityClass, RekeyService<?> rekeyService, ProgressTracker progressTracker,
							   RekeyCryptoShield rekeyCryptoShield, Function<RekeyService<?>, List<?>> recordsSupplier) {
		progressTracker.incrementBatchesProcessed();
		List<?> recordsToRekey = recordsSupplier.apply(rekeyService);
		if (recordsToRekey == null || recordsToRekey.isEmpty()) {
			logger.log(DEBUG, "No more records to re-key for entity {0}", entityClass.getName());
			return true;
		}

		logger.log(DEBUG, "Found {0} records to re-key for entity {1}", recordsToRekey.size(), entityClass.getName());
		for (Object entity : recordsToRekey) {
			rekeyEntity(entity, progressTracker, rekeyCryptoShield);
		}
		logger.log(DEBUG, "{0} records in batch {1} re-keyed for entity {2}....saving",
				progressTracker.getNumberOfRecordsProcessed() - progressTracker.getNumberOfRecordsFailed(),
				progressTracker.getNumberOfBatchesProcessed(), entityClass.getName());
		try {
			rekeyService.save(recordsToRekey);
		} catch (Exception e) {
			progressTracker.incrementNumberOfRecordsFailed();
			logger.log(WARNING, "An error occurred trying to save the {0} batch of records for entity {1}....skipping record",
					convertToOrdinal(progressTracker.getNumberOfBatchesProcessed()), entityClass.getName());
		}
		logger.log(DEBUG, () -> String.format("%s re-keyed records successfully saved for %s batch for entity %s (%s failed)",
				progressTracker.getNumberOfRecordsProcessed() - progressTracker.getNumberOfRecordsFailed(), convertToOrdinal(progressTracker.getNumberOfBatchesProcessed()),
				entityClass.getName(), progressTracker.getNumberOfRecordsFailed()));
		return false;
	}

	private void rekeyEntity(Object entity, ProgressTracker progressTracker, RekeyCryptoShield rekeyCryptoShield) {
		progressTracker.incrementRecordsProcessed();
		try {
			logger.log(TRACE, () -> String.format("Re-keying %s record in batch %s",
					convertToOrdinal(progressTracker.getNumberOfRecordsProcessed()), progressTracker.getNumberOfBatchesProcessed()));
			try {
				rekeyCryptoShield.decrypt(entity);
			} catch (Exception e) {
				logger.log(ERROR, "An error occurred trying to decrypt entity");
				throw new RuntimeException(e);
			}
			try {
				rekeyCryptoShield.encrypt(entity);
			} catch (Exception e) {
				logger.log(ERROR, "An error occurred trying to re-encrypt entity");
				throw new RuntimeException(e);
			}
			logger.log(TRACE, () -> String.format("%s record in batch %s re-keyed successfully",
					convertToOrdinal(progressTracker.getNumberOfRecordsProcessed()), progressTracker.getNumberOfBatchesProcessed()));
		} catch (Exception e) {
			progressTracker.incrementNumberOfRecordsFailed();
			logger.log(WARNING, "An error occurred trying to re-key the {0} record in the {1} batch of records for entity {2}....skipping record",
					convertToOrdinal(progressTracker.getNumberOfRecordsProcessed()), convertToOrdinal(progressTracker.getNumberOfBatchesProcessed()), entity.getClass().getName());
		}
	}

	private void removeKey(CryptoKey tenantsDeprecatedCryptoKey) {
		try {
			logger.log(INFO, "Notifying the application to mark the following Crypto key as deleted {1}", tenantsDeprecatedCryptoKey);
			rekeySchedulerConfig.getRekeyCryptoKeyManager().markKeyForDeletion(tenantsDeprecatedCryptoKey);
		} catch (Exception e) {
			logger.log(ERROR, "An error occurred trying to mark the Crypto key for deletion {}", tenantsDeprecatedCryptoKey);
		}
	}

	private static String convertToOrdinal(int i) {
		return switch (i % 100) {
			case 11, 12, 13 -> i + "th";
			default -> i + ORDINAL_SUFFIXES[i % 10];
		};
	}

	private Instant now() {
		return rekeySchedulerConfig.getClock().instant();
	}
}