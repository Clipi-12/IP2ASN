package me.clipi.ip2asn;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public record AS(int asn, @NotNull String countryCode) {
	public static final AS NULL_AS = new AS(0, "XX");

	@Override
	public boolean equals(Object other) {
		return other instanceof AS o && asn == o.asn;
	}

	public boolean exactMatch(@Nullable AS other) {
		return other != null && asn == other.asn && countryCode.equals(other.countryCode);
	}

	@Override
	public int hashCode() {
		return asn;
	}
}
