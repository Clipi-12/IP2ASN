package me.clipi.ip2asn.ip;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Objects;

public class IpRange<IpType extends InetAddress> {
	public final @NotNull BigInteger start, endInclusive;

	public final int ipTypeByteSize;
	/**
	 * It will be -1 if the range is not a CIDR block.
	 * <p>
	 * A range is not considered a CIDR block if it only covers one IP
	 */
	public final int cidrSize;

	public static final IpRange<Inet4Address> IPV4_RANGE = new IpRange<>(4);
	public static final IpRange<Inet6Address> IPV6_RANGE = new IpRange<>(16);

	private IpRange(int ipTypeByteSize) {
		this.start = BigInteger.ZERO;
		this.endInclusive = BigInteger.ONE.shiftLeft(ipTypeByteSize << 3).subtract(BigInteger.ONE);
		this.ipTypeByteSize = ipTypeByteSize;
		this.cidrSize = 0;
	}

	public IpRange(IpType start, int cidrSize) {
		byte[] startAddress = start.getAddress();
		int bitLen = startAddress.length << 3;
		if (cidrSize <= 0 || cidrSize > bitLen) throw new IllegalArgumentException(
			"start = " + start.getHostAddress() + ", cidrSize = " + cidrSize);
		this.start = new BigInteger(1, startAddress);
		BigInteger bitMask = BigInteger.ONE.shiftLeft(bitLen - cidrSize).subtract(BigInteger.ONE);
		if (this.start.and(bitMask).signum() != 0) throw new IllegalArgumentException(
			"start = " + start.getHostAddress() + ", cidrSize = " + cidrSize);
		this.endInclusive = this.start.or(bitMask);
		this.ipTypeByteSize = startAddress.length;
		this.cidrSize = cidrSize == bitLen ? -1 : cidrSize;
	}

	public IpRange(IpType start, IpType endInclusive) {
		byte[] startAddress = start.getAddress(), endInclusiveAddress = endInclusive.getAddress();
		if (startAddress.length != endInclusiveAddress.length) throw new IllegalArgumentException(
			"start and endInclusive must share the same protocol\nstart = " + start.getHostAddress() +
			", endInclusive = " + endInclusive.getHostAddress());
		this.start = new BigInteger(1, startAddress);
		this.endInclusive = new BigInteger(1, endInclusiveAddress);
		if (this.endInclusive.compareTo(this.start) <= 0)
			throw new IllegalArgumentException("start = " + start.getHostAddress() + ", endInclusive = " + endInclusive.getHostAddress());
		this.ipTypeByteSize = startAddress.length;
		this.cidrSize = -1;
	}

	IpRange(@NotNull BigInteger start, @NotNull BigInteger endInclusive, int ipTypeByteSize) {
		if (endInclusive.compareTo(start) <= 0)
			throw new IllegalArgumentException("start = " + start + ", endInclusive = " + endInclusive);
		this.start = start;
		this.endInclusive = endInclusive;
		this.ipTypeByteSize = ipTypeByteSize;
		this.cidrSize = -1;
	}

	@Override
	public boolean equals(Object other) {
		return other instanceof IpRange<?> o &&
			   ipTypeByteSize == o.ipTypeByteSize &&
			   start.equals(o.start) &&
			   endInclusive.equals(o.endInclusive);
	}

	@Override
	public int hashCode() {
		return Objects.hash(start, endInclusive);
	}

	public BigInteger size() {
		return endInclusive.subtract(start).add(BigInteger.ONE);
	}

	public boolean contains(IpType ip) {
		byte[] addr = ip.getAddress();
		BigInteger ip0 = new BigInteger(1, addr);
		return addr.length == ipTypeByteSize && ip0.compareTo(start) >= 0 && ip0.compareTo(endInclusive) <= 0;
	}

	@Override
	public String toString() {
		return "IpRange{\n\tstart=%s,\n\tendInclusive=%s\n}"
			.formatted(getStart().getHostAddress(), getEndInclusive().getHostAddress());
	}

	public IpType getStart() {
		return toIpType(getStartAsBytes());
	}

	public IpType getEndInclusive() {
		return toIpType(getEndInclusiveAsBytes());
	}

	@SuppressWarnings("unchecked")
	IpType toIpType(byte[] bytes) {
		try {
			return (IpType) (ipTypeByteSize == 4 ? InetAddress.getByAddress(bytes) :
				Inet6Address.getByAddress(null, bytes, null));
		} catch (UnknownHostException ex) {
			throw new AssertionError(ex);
		}
	}

	public byte[] getStartAsBytes() {
		return bigIntToAddr(start);
	}

	public byte[] getEndInclusiveAsBytes() {
		return bigIntToAddr(endInclusive);
	}

	private byte[] bigIntToAddr(BigInteger ip) {
		byte[] ipAddr = ip.toByteArray();
		if (ipAddr.length == ipTypeByteSize) return ipAddr;
		if (ipAddr.length > ipTypeByteSize) {
			assert ipAddr.length == ipTypeByteSize + 1;
			return Arrays.copyOfRange(ipAddr, 1, ipAddr.length);
		}
		byte[] res = new byte[ipTypeByteSize];
		System.arraycopy(ipAddr, 0, res, ipTypeByteSize - ipAddr.length, ipAddr.length);
		return res;
	}
}
