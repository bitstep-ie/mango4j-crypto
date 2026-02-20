package ie.bitstep.mango.crypto.testdata.entities.hmacstrategies.doublehmacstrategy;

import ie.bitstep.mango.crypto.annotations.Hmac;
import ie.bitstep.mango.crypto.annotations.HmacKeyId;
import ie.bitstep.mango.crypto.annotations.strategies.DoubleHmacStrategy;

@DoubleHmacStrategy
public class InvalidAnnotatedEntityForDoubleHmacFieldStrategyNonTransientHmacField {

	@Hmac
	private String pan;

	private String favouriteColor;

	@HmacKeyId
	private String hmacKeyId1;

	@HmacKeyId(keyNumber = 2)
	private String hmacKeyId2;

	public String getPan() {
		return pan;
	}

	public void setPan(String pan) {
		this.pan = pan;
	}

	public String getFavouriteColor() {
		return favouriteColor;
	}

	public void setFavouriteColor(String favouriteColor) {
		this.favouriteColor = favouriteColor;
	}
}