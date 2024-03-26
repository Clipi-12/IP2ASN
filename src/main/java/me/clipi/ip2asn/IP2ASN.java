package me.clipi.ip2asn;

import me.clipi.ip2asn.provider.TcpWhoisClient;
import me.clipi.ip2asn.provider.UdpDigWhoisClient;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
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
	@Nullable
	public final TcpWhoisClient fallbackTcp;

	public IP2ASN() {
		this(1_750);
	}

	@Override
	public void close() {
		try {
			if (fallbackTcp != null) fallbackTcp.close();
		} finally {
			if (fallbackUdp != null) fallbackUdp.close();
		}
	}

	public IP2ASN(long timeoutMillis) {
		fallbackUdp = UdpDigWhoisClient.createOrNull(
			hardcoded(8, 8, 8, 8),
			hardcoded(1, 1, 1, 1),
			"origin.asn.cymru.com", "origin6.asn.cymru.com", 53,
			timeoutMillis);

		{
			InetAddress whoisTcp;
			try {
				whoisTcp = InetAddress.getByName("whois.cymru.com");
			} catch (UnknownHostException ex) {
				LOGGER.log(Level.SEVERE, "DNS lookup failed during initialization", ex);
				// Just in case the DNS lookup fails, don't force the program to crash...
				whoisTcp = hardcoded(216, 31, 12, 15);
			}
			fallbackTcp = new TcpWhoisClient(whoisTcp, 43, timeoutMillis);
		}
	}


	@Nullable
	public AS ip2asn(@NotNull InetAddress ip) {
		// TODO Hay más ips que no tienen ASN (eg 0.0.0.0, 127.x.x.x)
		if (ip.isSiteLocalAddress()) return null;
		if (fallbackUdp != null) return fallbackUdp.ip2asn(ip);
		if (fallbackTcp != null) return fallbackTcp.ip2asn(ip);
		return null;
	}
}
