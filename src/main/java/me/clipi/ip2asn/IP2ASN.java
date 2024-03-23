package me.clipi.ip2asn;

import me.clipi.ip2asn.provider.UdpDigWhoisClient;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class IP2ASN implements IIP2ASN {
	private static InetAddress hardcoded(int... address) {
		byte[] arr = new byte[address.length];
		for (int i = 0; i < arr.length; ++i) arr[i] = (byte) address[i];
		try {
			return InetAddress.getByAddress(arr);
		} catch (UnknownHostException ex) {
			throw new AssertionError(ex);
		}
	}

	@Nullable
	private final UdpDigWhoisClient fallbackUdp;
	// @Nullable
	// private final TcpWhoisClient fallbackTcp;

	public IP2ASN() {
		this(3_000);
	}

	public IP2ASN(long timeoutMillis) {
		fallbackUdp = UdpDigWhoisClient.createOrNull(
			hardcoded(1, 1, 1, 1),
			"origin.asn.cymru.com", "origin6.asn.cymru.com", 53,
			timeoutMillis);

		// fallbackTcp = new TcpWhoisClient();
	}


	@Nullable
	public AS ip2asn(InetAddress ip) {
		if (fallbackUdp != null) return fallbackUdp.ip2asn(ip);
		// if (fallbackTcp != null) return fallbackTcp.ip2asn(ip);
		return null;
	}
}
