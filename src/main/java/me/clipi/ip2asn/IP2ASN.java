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
		this(2_500, 5_000);
	}

	@Override
	public void close() {
		try {
			if (fallbackTcp != null) fallbackTcp.close();
		} finally {
			if (fallbackUdp != null) fallbackUdp.close();
		}
	}

	public IP2ASN(long updPacketLossTimeoutMillis, long tcpTimeoutMillis) {
		fallbackUdp = UdpDigWhoisClient.createOrNull(
			hardcoded(8, 8, 8, 8),
			hardcoded(1, 1, 1, 1),
			"origin.asn.cymru.com", "origin6.asn.cymru.com", 53,
			updPacketLossTimeoutMillis);

		{
			InetAddress whoisTcp;
			try {
				whoisTcp = InetAddress.getByName("whois.cymru.com");
			} catch (UnknownHostException ex) {
				LOGGER.log(Level.SEVERE, "DNS lookup failed during initialization", ex);
				// Just in case the DNS lookup fails, don't force the program to crash...
				whoisTcp = hardcoded(216, 31, 12, 15);
			}
			fallbackTcp = new TcpWhoisClient(whoisTcp, 43, tcpTimeoutMillis);
		}
	}

	@Override
	@Nullable
	public AS v4ip2asn(byte @NotNull [] ip) {
		if (IIP2ASN.ipv4CannotHaveAS(ip)) return AS.NULL_AS;

		if (fallbackUdp != null) return fallbackUdp.v4ip2asn(ip);
		if (fallbackTcp != null) return fallbackTcp.v4ip2asn(ip);
		return null;
	}

	@Override
	@Nullable
	public AS v6ip2asn(byte @NotNull [] ip) {
		if (IIP2ASN.ipv6CannotHaveAS(ip)) return AS.NULL_AS;

		if (fallbackUdp != null) return fallbackUdp.v6ip2asn(ip);
		if (fallbackTcp != null) return fallbackTcp.v6ip2asn(ip);
		return null;
	}
}
