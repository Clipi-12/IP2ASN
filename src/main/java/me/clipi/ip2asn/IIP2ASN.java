package me.clipi.ip2asn;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;

public interface IIP2ASN extends AutoCloseable {
	@Nullable
	default AS ip2asn(@NotNull InetAddress ip) {
		byte[] ipAddress = ip.getAddress();
		return ipAddress.length == 4 ? v4ip2asn(ipAddress) : v6ip2asn(ipAddress);
	}

	/**
	 * @param ip an IPv4.
	 *           <ul>
	 *           	<li>The array must contain 4 octets.</li>
	 *           	<li>The array must remain immutable for the duration of the call.</li>
	 *           </ul>
	 */
	@Nullable
	default AS v4ip2asn(byte @NotNull [] ip) {
		try {
			// TODO Temp solution
			return ip2asn(InetAddress.getByAddress(ip));
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * @param ip an IPv6.
	 *           <ul>
	 *           	<li>The array must contain 16 octets.</li>
	 *           	<li>The array must remain immutable for the duration of the call.</li>
	 *           </ul>
	 */
	@Nullable
	default AS v6ip2asn(byte @NotNull [] ip) {
		try {
			// TODO Temp solution
			return ip2asn(InetAddress.getByAddress(ip));
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	void close();

	/**
	 * @param ip an IPv4.
	 *           <ul>
	 *           	<li>The array must contain 4 octets.</li>
	 *           	<li>The array must remain immutable for the duration of the call.</li>
	 *           </ul>
	 */
	static boolean ipv4CannotHaveAS(byte @NotNull [] ip) {
		assert ip.length == 4;

		// See https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
		int oc1 = ip[0] & 0xFF, oc2 = ip[1] & 0xFF;
		return (
				   oc1 == 0 || oc1 == 10 ||
				   oc1 == 127 // TODO https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml#note1
				   || (oc1 & 0xF0) == 240
			   ) ||
			   (
				   oc1 == 100 && (oc2 & 0xC0) == 64
			   ) ||
			   (
				   oc1 == 169 && oc2 == 254
			   ) ||
			   (
				   oc1 == 172 && (oc2 & 0xF0) == 16
			   ) ||
			   (
				   oc1 == 192 && (
					   (oc2 == 0 && (
						   (ip[2] == 0 && (
							   (ip[3] & 0xF8) == 0 ||
							   ip[3] == 8 ||
							   (ip[3] & 0xFE) == 170
						   )) ||
						   (ip[2] == 2)
					   )) ||
					   (oc2 == 168)
				   )
			   ) ||
			   (
				   oc1 == 198 && (
					   ((oc2 & 0xFE) == 18) ||
					   (oc2 == 51 && ip[2] == 100)
				   )
			   ) ||
			   (
				   oc1 == 203 && oc2 == 0 &&
				   ip[2] == 113
			   ) ||
			   (
				   oc1 == 255 && oc2 == 255 &&
				   (ip[2] & 0xFF) == 255 && (ip[3] & 0xFF) == 255
			   );
	}

	/**
	 * @param ip an IPv6.
	 *           <ul>
	 *           	<li>The array must contain 16 octets.</li>
	 *           	<li>The array must remain immutable for the duration of the call.</li>
	 *           </ul>
	 */
	static boolean ipv6CannotHaveAS(byte @NotNull [] ip) {
		assert ip.length == 16;

		// See https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
		byte oc1 = ip[0], oc2 = ip[1], oc3 = ip[2], oc4 = ip[3], oc5 = ip[4], oc6 = ip[5];
		return (
				   (oc1 & 0xFE) == 0xfc
			   ) ||
			   (
				   (oc1 & 0xFF) == 0xfe && (oc2 & 0xC0) == 0x80
			   ) ||
			   (
				   oc1 == 0 && (oc2 & 0xFF) == 0x64 &&
				   (oc3 & 0xFF) == 0xff && (oc4 & 0xFF) == 0x9b &&
				   oc5 == 0 && oc6 == 1
			   ) ||
			   (
				   oc2 == 0 &&
				   oc3 == 0 && oc4 == 0 &&
				   oc5 == 0 && oc6 == 0 &&
				   ip[6] == 0 && ip[7] == 0 && (
					   (oc1 == 1) ||
					   (oc1 == 0 && ip[8] == 0 && ip[9] == 0 && (
						   (
							   ip[10] == 0 && ip[11] == 0 &&
							   ip[12] == 0 && ip[13] == 0 &&
							   ip[14] == 0 && (ip[15] & 0xFE) == 0
						   ) ||
						   (
							   (ip[10] & 0xFF) == 0xff && (ip[11] & 0xFF) == 0xff
						   )
					   ))
				   )
			   ) ||
			   (
				   oc1 == 0x20 && oc2 == 1 && (
					   (
						   oc3 == 0 && oc4 == 2 &&
						   oc5 == 0 && oc6 == 0
					   ) ||
					   (
						   oc3 == 0x0d && (oc4 & 0xFF) == 0xb8
					   )
				   )
			   );
	}
}
