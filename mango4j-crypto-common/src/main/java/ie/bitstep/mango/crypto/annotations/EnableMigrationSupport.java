package ie.bitstep.mango.crypto.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Field-level annotation that marks a non-transient field as temporarily participating in encrypted-blob migration.
 * This annotation should be used when migrating encryption implementations across large datasets where immediate
 * migration is not feasible.
 * <p>
 * <p>
 * Before the {@code completedBy} date, the presence of this annotation will result in a warning logged
 * at application startup. After the {@code completedBy} date, this will become an error.
 * <p>
 * <p>
 * <p>
 * Example usage:
 *
 * @EnableMigrationSupport( completedBy = "2026-03-31",
 * justification = "Backfill via crypto rekey job across large dataset",
 * ticket = "OBS-1432"
 * )
 * private String email; // NOTE: previously unencrypted field, non-transient
 *
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface EnableMigrationSupport {

	/**
	 * The date by which the migration should be completed and this annotation removed.
	 * Format: ISO-8601 date string (YYYY-MM-DD).
	 *
	 * @return the migration completion deadline in ISO-8601 format
	 */
	String completedBy();

	/**
	 * Justification for why migration support is needed for this field.
	 *
	 * @return the justification text
	 */
	String justification();

	/**
	 * Optional ticket or issue reference related to this migration.
	 *
	 * @return the ticket reference, defaults to empty string
	 */
	String ticket() default "";
}