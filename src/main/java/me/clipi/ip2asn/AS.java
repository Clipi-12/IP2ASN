package me.clipi.ip2asn;

public record AS(int asn, String countryCode) {
	public static final AS NULL_AS = new AS(0, "XX");
}
