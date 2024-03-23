package me.clipi.ip2asn;

import me.clipi.ip2asn.provider.UdpDigWhoisClient;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Logger;

public class IP2ASN implements IIP2ASN {
	private static final Logger LOGGER = Logger.getLogger("IP2ASN");

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
	public final UdpDigWhoisClient fallbackUdp;
	// @Nullable
	// public final TcpWhoisClient fallbackTcp;

	public IP2ASN() {
		this(1_750);
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
