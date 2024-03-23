package me.clipi.ip2asn.provider;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.IP2ASN;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.lang.invoke.VarHandle;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * <p>
 * <a href="https://www.rfc-editor.org/rfc/rfc1035.html">RFC 1035</a>
 * <p>
 * <a href="https://levelup.gitconnected.com/dns-request-and-response-in-java-acbd51ad3467">Medium article</a>
 */
public class UdpDigWhoisClient implements IIP2ASN, AutoCloseable {
	private static final Logger LOGGER;

	static {
		// Initialize logger's parent
		// noinspection ResultOfMethodCallIgnored
		IP2ASN.class.getClass();
		LOGGER = Logger.getLogger("IP2ASN.UdpDigWhoisClient");
	}

	private final InetAddress hostDns;
	private final byte[] whoisHostV4, whoisHostV6;
	private final int port;
	private final long timeoutMillis;
	private final DatagramSocket socket;
	private final String[] asCountryCodeResult = new String[0x10000];
	private final int[] asnResult = new int[0x10000];
	private final Thread[] requesters = new Thread[0x10000];
	private final AtomicInteger id = new AtomicInteger();


	private volatile boolean isAlive = true;
	private final Thread udpListener;

	@Override
	public void close() {
		isAlive = false;
		LockSupport.unpark(udpListener);
	}

	private static byte[] domainToLabels(String domain) {
		Byte[] ret = Arrays.stream(domain.split("\\."))
						   .flatMap(s -> {
							   byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
							   List<Byte> res = new ArrayList<>();
							   res.add((byte) bytes.length);
							   for (byte b : bytes) res.add(b);
							   return res.stream();
						   }).toArray(Byte[]::new);
		byte[] arr = new byte[ret.length];
		for (int i = 0; i < arr.length; ++i) arr[i] = ret[i];
		return arr;
	}

	@Nullable
	public static UdpDigWhoisClient createOrNull(InetAddress hostDns, String whoisHostV4, String whoisHostV6, int port,
												 long timeoutMillis) {
		try {
			return new UdpDigWhoisClient(hostDns, whoisHostV4, whoisHostV6, port, timeoutMillis);
		} catch (SocketException ex) {
			return null;
		}
	}

	@Nullable
	public static UdpDigWhoisClient createOrNull(InetAddress hostDns, byte[] whoisHostV4, byte[] whoisHostV6, int port,
												 long timeoutMillis) {
		try {
			return new UdpDigWhoisClient(hostDns, whoisHostV4, whoisHostV6, port, timeoutMillis);
		} catch (SocketException ex) {
			return null;
		}
	}

	public UdpDigWhoisClient(InetAddress hostDns, String whoisHostV4, String whoisHostV6, int port,
							 long timeoutMillis) throws SocketException {
		this(hostDns, domainToLabels(whoisHostV4), domainToLabels(whoisHostV6), port, timeoutMillis);
	}


	public UdpDigWhoisClient(InetAddress hostDns, byte[] whoisHostV4, byte[] whoisHostV6, int port,
							 long timeoutMillis) throws SocketException {
		this.hostDns = hostDns;
		this.whoisHostV4 = whoisHostV4;
		this.whoisHostV6 = whoisHostV6;
		this.port = port;
		this.timeoutMillis = timeoutMillis;
		socket = new DatagramSocket();
		socket.setSoTimeout(5_000);

		udpListener = new Thread(() -> {
			final int THEORETICAL_UDP_LIMIT = 0x10000;
			byte[] response = new byte[THEORETICAL_UDP_LIMIT];
			DatagramPacket packet = new DatagramPacket(response, response.length);

			int[] asn_cidrMask_offset = { 0, 0, 0 };
			String[] asCC = { null };


			listen:
			while (isAlive) {
				try {
					socket.receive(packet);
				} catch (SocketTimeoutException ignored) {
					LockSupport.park();
					continue;
				} catch (IOException ex) {
					LOGGER.log(Level.SEVERE, "Socket exception while receiving data", ex);
					break;
				}
				int length = packet.getLength();
				if (length > THEORETICAL_UDP_LIMIT) continue;

				final int ANCOUNT = shortFromBytes(response[6], response[7]);

				// Assert correct header
				if (!(
					12 < length &&
					(response[2] & 0b1111_1011) == 0b1000_0001 &&
					(response[3] & 0b0111_1111) == 0 &&
					response[4] == 0 &&
					response[5] == 1 &&
					ANCOUNT > 0 &&
					response[8] == 0 &&
					response[9] == 0 &&
					response[10] == 0 &&
					response[11] == 0
				)) {
					warnUnexpectedPacketReceived(response, length, 1);
					continue;
				}

				int offset = 12;
				// noinspection StatementWithEmptyBody
				while (response[offset++] != 0 && offset < length) {
				}
				// Assert correct question
				if (!(
					offset + 5 < length &&
					response[offset] == 0 &&
					response[offset + 1] == 16 &&
					response[offset + 2] == 0 &&
					response[offset + 3] == 1
				)) {
					warnUnexpectedPacketReceived(response, length, 2);
					continue;
				}


				asn_cidrMask_offset[0] = 0;
				asn_cidrMask_offset[1] = 0;
				asn_cidrMask_offset[2] = offset + 4;
				asCC[0] = null;
				for (int i = 0; i < ANCOUNT; ++i) {
					if (!readTxtAnswer(response, length, asn_cidrMask_offset, asCC))
						continue listen;
				}
				if (asn_cidrMask_offset[2] != length) {
					warnUnexpectedPacketReceived(response, length, 9);
					continue;
				}
				int id = shortFromBytes(response[0], response[1]);

				asnResult[id] = asn_cidrMask_offset[0];
				VarHandle.fullFence();
				asCountryCodeResult[id] = asCC[0];
				VarHandle.fullFence();
				LockSupport.unpark(requesters[id]);
			}

			socket.close();
		});
		udpListener.start();
	}

	private static int shortFromBytes(byte high, byte low) {
		return ((high & 0xFF) << 8) | (low & 0xFF);
	}

	private static boolean readTxtAnswer(byte[] response, int length, int[] asn_cidrMask_offset, String[] asCC) {
		int offset = asn_cidrMask_offset[2];
		try {
			while (offset < length) {
				int resHigh = response[offset++] & 0xFF;
				if (resHigh == 0) break;
				int res2MSB = resHigh >>> 6;
				if (res2MSB == 0) {
					offset += resHigh & 0b0011_1111;
					continue;
				}
				if (res2MSB < 3) {
					warnUnexpectedPacketReceived(response, length, 3);
					return false;
				}
				// Skip low octet of message compression
				++offset;
				// Once a pointer has been reached, the string is terminated, as per https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.4
				break;
			}
			// Assert correct answer
			if (!(
				offset + 9 < length &&
				response[offset] == 0 &&
				response[offset + 1] == 16 &&
				response[offset + 2] == 0 &&
				response[offset + 3] == 1
			)) {
				warnUnexpectedPacketReceived(response, length, 4);
				return false;
			}
			offset += 10;
			int textLength = shortFromBytes(response[offset - 2], response[offset - 1]);
			final int endOfAnswer = offset + textLength;
			if ((response[offset++] & 0xFF) + 1 != textLength) {
				warnUnexpectedPacketReceived(response, length, 5);
				return false;
			}

			asn_cidrMask_offset[2] = offset;
			long asn = readShortUntilPipe(response, length, asn_cidrMask_offset, 0);
			if (asn == -1) return false;
			asn &= 0xFFFF_FFFFL;
			offset = asn_cidrMask_offset[2];

			final int ipResponseOffset = offset;
			// noinspection StatementWithEmptyBody
			while (response[offset++] != '/') {
			}
			asn_cidrMask_offset[2] = offset;
			long cidrMask = readShortUntilPipe(response, length, asn_cidrMask_offset, -1);
			if (cidrMask == -1) return false;
			final int ipResponseLen = offset - ipResponseOffset + (int) (cidrMask >>> 32);
			cidrMask &= 0xFFFF_FFFFL;
			offset = asn_cidrMask_offset[2];

			final int countryCodeResponseOffset = offset;
			while (response[offset] != ' ' && response[offset] != '|') ++offset;
			final int countryCodeResponseLen = offset - countryCodeResponseOffset;

			final Level logLevel = Level.FINE;
			if (LOGGER.isLoggable(logLevel)) LOGGER.log(
				logLevel, "DNS response of IP->ASN (" + new String(
					// TODO Is it really UTF-8?
					response, ipResponseOffset, ipResponseLen, StandardCharsets.UTF_8) + " -> " + asn + ")");

			if (cidrMask > asn_cidrMask_offset[1]) {
				asn_cidrMask_offset[0] = (int) asn;
				asn_cidrMask_offset[1] = (int) cidrMask;
			}

			// TODO Should we do checks like countryCodeResponseLen==2 ?
			//  ISO-3166 has a variant of 3 characters (https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
			String asCountryCode = new String(
				// TODO Is it really UTF-8? In that case, the previous TODO should not refer to
				//  countryCodeResponseLen (byte length), but the char-length
				response, countryCodeResponseOffset, countryCodeResponseLen, StandardCharsets.UTF_8);
			if (asCC[0] == null) asCC[0] = asCountryCode;
			if (!asCC[0].equals(asCountryCode)) {
				warnUnexpectedPacketReceived(response, length, 8);
				return false;
			}

			offset = endOfAnswer;
			return true;
		} finally {
			asn_cidrMask_offset[2] = offset;
		}
	}

	private static long readShortUntilPipe(byte[] response, int length, int[] asn_cidrMask_offset, int recursion) {
		int offset = asn_cidrMask_offset[2];
		int numByteLength = 0;
		int num = 0;
		do {
			int digit = response[offset++] & 0xFF;
			if (digit == '|') break;
			if (digit == ' ') {
				final int firstSpace = offset - 1;
				while (response[offset] == ' ') ++offset;
				if (response[offset] == '|') {
					++offset;
					break;
				}
				// If an ip has multiple ASNs associated with it (which should be impossible,
				// but in reality it may occur), just return the lowest ASN
				if (response[offset] >= '0' && response[offset] <= '9' && recursion >= 0 && recursion < 5) {
					asn_cidrMask_offset[2] = offset;
					long next = readShortUntilPipe(response, length, asn_cidrMask_offset, recursion + 1);
					numByteLength += (int) (next >>> 32) + offset - firstSpace;
					next &= 0xFFFF_FFFFL;
					return ((long) numByteLength << 32) | (num < next ? num : next);
				}
				warnUnexpectedPacketReceived(response, length, 7);
				return -1;
			}
			digit -= '0';
			if (digit < 0 || digit > 9) {
				warnUnexpectedPacketReceived(response, length, 6);
				return -1;
			}
			num *= 10;
			num += digit;
			++numByteLength;
		} while (true);
		while (response[offset] == ' ') ++offset;
		asn_cidrMask_offset[2] = offset;
		return ((long) numByteLength << 32) | num;
	}

	private static void warnUnexpectedPacketReceived(byte[] response, int length, int errno) {
		LOGGER.warning("Received unexpected message (will get ignored, errno=" + errno + "): " +
					   Arrays.toString(Arrays.copyOf(response, length)));
	}

	@Override
	public @Nullable AS ip2asn(InetAddress ip) {
		byte[] ipAddress = ip.getAddress();
		boolean isIPV6 = ip instanceof Inet6Address;
		int whoisHostOffset = 12 + (isIPV6 ? 64 : ipv4EncodingLength(ipAddress));
		byte[] whoisHost = isIPV6 ? whoisHostV6 : whoisHostV4;
		byte[] req =
			new byte[whoisHostOffset + whoisHost.length + 5];

		int id = this.id.incrementAndGet() & 0xFFFF;
		req[0] = (byte) (id >>> 8);
		req[1] = (byte) id;
		// RD Flag
		req[2] = 1;
		// QDCOUNT
		req[5] = 1;
		// TXT
		req[req.length - 3] = 16;
		// IN
		req[req.length - 1] = 1;

		// See https://stackoverflow.com/a/18639042
		// System.arraycopy(whoisHost, 0, req, whoisHostOffset, whoisHost.length);
		for (int i = 0, iOffset = whoisHostOffset, s = whoisHost.length; i < s; ++i, ++iOffset)
			req[iOffset] = whoisHost[i];

		if (isIPV6) {
			encodeIPv6(ipAddress, req);
		} else {
			encodeIPv4(ipAddress, req);
		}

		requesters[id] = Thread.currentThread();
		DatagramPacket udpPacket = new DatagramPacket(req, req.length, hostDns, port);
		int udpTries = 3;
		fetch:
		do {
			final long until = System.currentTimeMillis() + timeoutMillis;
			try {
				socket.send(udpPacket);
			} catch (IOException ex) {
				LOGGER.log(Level.SEVERE, "Socket exception while sending data", ex);
				requesters[id] = null;
				return null;
			}

			if (!isAlive) {
				requesters[id] = null;
				return null;
			}
			LockSupport.unpark(udpListener);

			String countryCode;
			VarHandle.fullFence();
			do {
				countryCode = asCountryCodeResult[id];
				if (countryCode != null) break;
				// The packet probably got lost
				if (System.currentTimeMillis() > until) continue fetch;
				LockSupport.parkUntil(until);
			} while (true);
			VarHandle.fullFence();

			int asn = asnResult[id];
			asCountryCodeResult[id] = null;
			requesters[id] = null;
			return new AS(asn, countryCode);
		} while (--udpTries > 0);

		return null;
	}

	private static void encodeIPv6(byte[] ip, byte[] out) {
		assert ip.length == 16;
		for (int i = 15, res = 12; i >= 0; --i, res += 4) {
			out[res] = 1;
			out[res + 2] = 1;

			int nibble;
			nibble = ip[i] & 0xF;
			out[res + 1] = (byte) (nibble + (nibble >= 10 ? 'a' - 10 : '0'));
			nibble = (ip[i] >>> 4) & 0xF;
			out[res + 3] = (byte) (nibble + (nibble >= 10 ? 'a' - 10 : '0'));
		}
	}

	private static int ipv4EncodingLength(byte[] ip) {
		assert ip.length == 4;
		assert ipv4EncodingLengthPerOctet.length == 256;
		return ipv4EncodingLengthPerOctet[ip[0] & 0xFF] +
			   ipv4EncodingLengthPerOctet[ip[1] & 0xFF] +
			   ipv4EncodingLengthPerOctet[ip[2] & 0xFF] +
			   ipv4EncodingLengthPerOctet[ip[3] & 0xFF] + 4;
	}


	private static void encodeIPv4(byte[] ip, byte[] out) {
		assert ip.length == 4;
		assert digitsOnes.length == 256;
		assert digitsTens.length == 256;
		assert digitsHundreds.length == 256;
		for (int i = 3, res = 12; i >= 0; --i) {
			final int octet = ip[i] & 0xFF;
			out[res++] = ipv4EncodingLengthPerOctet[octet];
			if (octet >= 100) out[res++] = digitsHundreds[octet];
			if (octet >= 10) out[res++] = digitsTens[octet];
			out[res++] = digitsOnes[octet];
		}
	}

	private static final byte[] ipv4EncodingLengthPerOctet = {
		// [0, 9]
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1,

		// [10, 99]
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2,

		// [100, 255]
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
		3, 3, 3, 3, 3, 3
	};

	private static final byte[] digitsOnes = {
		// [0, 255]
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'0', '1', '2', '3', '4', '5',
		};
	private static final byte[] digitsTens = {
		// [0, 99]
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'3', '3', '3', '3', '3', '3', '3', '3', '3', '3',
		'4', '4', '4', '4', '4', '4', '4', '4', '4', '4',
		'5', '5', '5', '5', '5', '5', '5', '5', '5', '5',
		'6', '6', '6', '6', '6', '6', '6', '6', '6', '6',
		'7', '7', '7', '7', '7', '7', '7', '7', '7', '7',
		'8', '8', '8', '8', '8', '8', '8', '8', '8', '8',
		'9', '9', '9', '9', '9', '9', '9', '9', '9', '9',
		// [100, 199]
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'3', '3', '3', '3', '3', '3', '3', '3', '3', '3',
		'4', '4', '4', '4', '4', '4', '4', '4', '4', '4',
		'5', '5', '5', '5', '5', '5', '5', '5', '5', '5',
		'6', '6', '6', '6', '6', '6', '6', '6', '6', '6',
		'7', '7', '7', '7', '7', '7', '7', '7', '7', '7',
		'8', '8', '8', '8', '8', '8', '8', '8', '8', '8',
		'9', '9', '9', '9', '9', '9', '9', '9', '9', '9',
		// [200, 255]
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'3', '3', '3', '3', '3', '3', '3', '3', '3', '3',
		'4', '4', '4', '4', '4', '4', '4', '4', '4', '4',
		'5', '5', '5', '5', '5', '5',
		};
	private static final byte[] digitsHundreds = {
		// [0, 90]
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
		// [100, 199]
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		'1', '1', '1', '1', '1', '1', '1', '1', '1', '1',
		// [200, 255]
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'2', '2', '2', '2', '2', '2', '2', '2', '2', '2',
		'2', '2', '2', '2', '2', '2',
		};
}
