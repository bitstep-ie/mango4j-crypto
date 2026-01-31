package ie.bitstep.mango.crypto.keyrotation;

import ie.bitstep.mango.crypto.keyrotation.exceptions.TooManyFailuresException;

public class ProgressTracker {

	private final int maxFailureCountPerExecution;
	private int numberOfRecordsProcessed = 0;
	private int numberOfRecordsFailed = 0;
	private int numberOfBatchesProcessed = 0;

	/**
	 * Creates a progress tracker with a failure threshold.
	 *
	 * @param maxFailureCountPerExecution the maximum failures allowed per execution
	 */
	public ProgressTracker(int maxFailureCountPerExecution) {
		this.maxFailureCountPerExecution = maxFailureCountPerExecution;
	}

	/**
	 * Increments the processed records count.
	 */
	public void incrementRecordsProcessed() {
		numberOfRecordsProcessed += 1;
	}

	/**
	 * Increments the processed batches count.
	 */
	public void incrementBatchesProcessed() {
		numberOfBatchesProcessed += 1;
	}

	/**
	 * Increments failed records and throws if the threshold is exceeded.
	 */
	public void incrementNumberOfRecordsFailed() {
		if (++numberOfRecordsFailed > maxFailureCountPerExecution && maxFailureCountPerExecution >= 0) {
			throw new TooManyFailuresException(
				String.format("Max errors threshold of %d per execution exceeded while processing records, failure count=%d",
					maxFailureCountPerExecution, numberOfRecordsFailed));
		}
	}

	/**
	 * Returns the number of batches processed.
	 *
	 * @return the batches processed count
	 */
	public int getNumberOfBatchesProcessed() {
		return numberOfBatchesProcessed;
	}

	/**
	 * Returns the number of records failed.
	 *
	 * @return the failed records count
	 */
	public int getNumberOfRecordsFailed() {
		return numberOfRecordsFailed;
	}

	/**
	 * Returns the number of records processed.
	 *
	 * @return the processed records count
	 */
	public int getNumberOfRecordsProcessed() {
		return numberOfRecordsProcessed;
	}
}
