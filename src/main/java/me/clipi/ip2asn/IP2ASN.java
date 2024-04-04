package me.clipi.ip2asn;

import me.clipi.ip2asn.provider.TcpWhoisClient;
import me.clipi.ip2asn.provider.UdpDigWhoisClient;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.function.BiFunction;
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

	@NotNull
	final IIP2ASN main;

	final @NotNull IIP2ASN @NotNull [] fallbacks;

	@Nullable
	public static IP2ASN createDefault() {
		return createDefault(Duration.ofMillis(2_500), Duration.ofSeconds(5), 0, 0);
	}

	public static IP2ASN createDefault(Duration updPacketLossTimeout, Duration tcpTimeout,
									   int localUdpPort, int localTcpPort) {
		ArrayList<IIP2ASN> list = new ArrayList<>();

		list.add(UdpDigWhoisClient.createOrNull(
			hardcoded(8, 8, 8, 8),
			hardcoded(1, 1, 1, 1),
			"origin.asn.cymru.com", "origin6.asn.cymru.com", 53, localUdpPort,
			updPacketLossTimeout, LOGGER));

		{
			InetAddress whoisTcp;
			try {
				whoisTcp = InetAddress.getByName("whois.cymru.com");
			} catch (UnknownHostException ex) {
				LOGGER.log(Level.SEVERE, "DNS lookup failed during initialization", ex);
				// Just in case the DNS lookup fails, don't force the program to crash...
				whoisTcp = hardcoded(216, 31, 12, 15);
			}
			list.add(new TcpWhoisClient(whoisTcp, 43, localTcpPort, tcpTimeout));
		}

		// noinspection StatementWithEmptyBody
		while (list.remove(null)) ;

		if (list.isEmpty()) return null;
		return new IP2ASN(list.get(0), list.subList(1, list.size()).toArray(IIP2ASN[]::new));
	}

	public IP2ASN(@NotNull IIP2ASN main, @NotNull IIP2ASN @NotNull ... fallbacks) {
		this.main = main;
		this.fallbacks = fallbacks;
	}

	@Override
	public void close() {
		main.close();
		for (IIP2ASN fallback : fallbacks) fallback.close();
	}

	@Override
	@Nullable
	public AS v4ip2asn(byte @NotNull [] ip) {
		return IIP2ASN.ipv4CannotHaveAS(ip) ? AS.NULL_AS : ip2asn(ip, IIP2ASN::v4ip2asn, true);
	}

	@Override
	@Nullable
	public AS v6ip2asn(byte @NotNull [] ip) {
		return IIP2ASN.ipv6CannotHaveAS(ip) ? AS.NULL_AS : ip2asn(ip, IIP2ASN::v6ip2asn, false);
	}

	private static final byte[] forIpStr = " for ip ".getBytes(StandardCharsets.US_ASCII);

	private AS ip2asn(byte[] ip, BiFunction<IIP2ASN, byte[], AS> func, boolean isIpv4) {
		AS res = func.apply(main, ip);
		if (res == null) {
			String ip0;
			{
				byte[] buf = Arrays.copyOf(forIpStr, forIpStr.length + (isIpv4 ?
					IP2ExpandedString.ipv4StringLength :
					IP2ExpandedString.ipv6StringLength));
				ip0 = new String(isIpv4 ?
									 IP2ExpandedString.ipv4ToString(ip, buf, forIpStr.length) :
									 IP2ExpandedString.ipv6ToString(ip, buf, forIpStr.length),
								 StandardCharsets.US_ASCII);
			}
			for (int i = 0, s = fallbacks.length; res == null && i < s; ++i) {
				IIP2ASN fallback = fallbacks[i];
				LOGGER.warning("Falling back to " + fallback.getClass().getSimpleName() + ip0);
				res = func.apply(fallback, ip);
			}
		}
		return res;
	}
}
