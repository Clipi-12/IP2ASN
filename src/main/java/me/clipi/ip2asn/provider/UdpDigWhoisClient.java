package me.clipi.ip2asn.provider;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.IP2ASN;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
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
import java.util.stream.IntStream;

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

	private final InetAddress[] hostDns = new InetAddress[2];
	private final byte[] whoisHostV4, whoisHostV6;
	private final int port;
	private final long timeoutMillis;
	private final DatagramSocket socket;
	private final Thread[] requesters = new Thread[0x10000];
	private final byte[][] requesterBufs = new byte[0x10000][];
	private final AtomicInteger id = new AtomicInteger();


	private volatile boolean isAlive = true;
	private final Thread[] udpListeners;

	private void wakeupListeners() {
		for (Thread udpListener : udpListeners)
			LockSupport.unpark(udpListener);
	}

	@Override
	public void close() {
		isAlive = false;
		wakeupListeners();
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
		return createOrNull(hostDns, hostDns, whoisHostV4, whoisHostV6, port, timeoutMillis);
	}

	@Nullable
	public static UdpDigWhoisClient createOrNull(InetAddress hostDns, InetAddress fallbackHostDns,
												 String whoisHostV4, String whoisHostV6, int port,
												 long timeoutMillis) {
		return createOrNull(hostDns, fallbackHostDns, domainToLabels(whoisHostV4), domainToLabels(whoisHostV6), port,
							timeoutMillis);
	}

	@Nullable
	public static UdpDigWhoisClient createOrNull(InetAddress hostDns, byte[] whoisHostV4, byte[] whoisHostV6, int port,
												 long timeoutMillis) {
		return createOrNull(hostDns, hostDns, whoisHostV4, whoisHostV6, port, timeoutMillis);
	}

	@Nullable
	public static UdpDigWhoisClient createOrNull(InetAddress hostDns, InetAddress fallbackHostDns,
												 byte[] whoisHostV4, byte[] whoisHostV6, int port,
												 long timeoutMillis) {
		try {
			return new UdpDigWhoisClient(hostDns, fallbackHostDns, whoisHostV4, whoisHostV6, port, timeoutMillis);
		} catch (SocketException ex) {
			return null;
		}
	}

	private static final int THEORETICAL_UDP_LIMIT = 0xFFFF;

	public UdpDigWhoisClient(InetAddress hostDns, InetAddress fallbackHostDns, byte[] whoisHostV4, byte[] whoisHostV6,
							 int port,
							 long timeoutMillis) throws SocketException {
		this.hostDns[1] = hostDns;
		this.hostDns[0] = fallbackHostDns;
		this.whoisHostV4 = whoisHostV4;
		this.whoisHostV6 = whoisHostV6;
		this.port = port;
		this.timeoutMillis = timeoutMillis;
		socket = new DatagramSocket();
		socket.setSoTimeout(5_000);

		udpListeners = IntStream.range(0, 3).mapToObj(_idx -> new Thread(() -> {
			byte[] response = new byte[THEORETICAL_UDP_LIMIT];
			DatagramPacket packet = new DatagramPacket(response, response.length);

			while (isAlive) {
				try {
					socket.receive(packet);
				} catch (SocketTimeoutException ignored) {
					LockSupport.park();
					continue;
				} catch (IOException ex) {
					LOGGER.log(Level.SEVERE, "Socket exception while receiving data", ex);
					continue;
				}
				int length = packet.getLength();
				if (length > THEORETICAL_UDP_LIMIT) continue;

				int id = shortFromBytes(response[0], response[1]);
				byte[] requesterBuf = (byte[]) BYTE_ARR_ARR_HANDLE.getVolatile(requesterBufs, id);
				if (requesterBuf == null) {
					warnUnexpectedPacketReceived(response, length, 0);
					continue;
				}
				System.arraycopy(response, 0, requesterBuf, 0, length);
				requesterBuf[THEORETICAL_UDP_LIMIT - 1] = (byte) length;
				requesterBuf[THEORETICAL_UDP_LIMIT - 2] = (byte) (length >>> 8);
				final byte ZERO = 0;
				BYTE_ARR_HANDLE.setVolatile(requesterBuf, THEORETICAL_UDP_LIMIT, ZERO);
				LockSupport.unpark(requesters[id]);
			}

			socket.close();
		})).toArray(Thread[]::new);
		for (Thread udpListener : udpListeners)
			udpListener.start();
	}

	private static final ThreadLocal<byte[]> response =
		ThreadLocal.withInitial(() -> new byte[THEORETICAL_UDP_LIMIT + 3]);

	private static final VarHandle
		BYTE_ARR_HANDLE = MethodHandles.arrayElementVarHandle(byte[].class),
		BYTE_ARR_ARR_HANDLE = MethodHandles.arrayElementVarHandle(byte[][].class);

	private AS decode(final byte[] response) {
		final int length = shortFromBytes(response[THEORETICAL_UDP_LIMIT - 2], response[THEORETICAL_UDP_LIMIT - 1]);
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
			return null;
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
			return null;
		}

		int[] asn_cidrMask_offset_asCcOffset_asCcLen = { 0, 0, offset + 4, 0, 0 };
		for (int i = 0; i < ANCOUNT; ++i) {
			if (!readTxtAnswer(response, length, asn_cidrMask_offset_asCcOffset_asCcLen))
				return null;
		}
		if (asn_cidrMask_offset_asCcOffset_asCcLen[2] != length) {
			warnUnexpectedPacketReceived(response, length, 8);
			return null;
		}
		String asCountryCode = new String(
			// TODO Is it really UTF-8? In that case, the check of ISO-3166 should not
			//  refer to countryCodeResponseLen (byte length), but the char-length
			response, asn_cidrMask_offset_asCcOffset_asCcLen[3], asn_cidrMask_offset_asCcOffset_asCcLen[4],
			StandardCharsets.UTF_8);

		return new AS(asn_cidrMask_offset_asCcOffset_asCcLen[0], asCountryCode);
	}

	private static int shortFromBytes(byte high, byte low) {
		return ((high & 0xFF) << 8) | (low & 0xFF);
	}

	private static boolean readTxtAnswer(byte[] response, int length, int[] asn_cidrMask_offset_asCcOffset_asCcLen) {
		int offset = asn_cidrMask_offset_asCcOffset_asCcLen[2];
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

			asn_cidrMask_offset_asCcOffset_asCcLen[2] = offset;
			long asn = readShortUntilPipe(response, length, asn_cidrMask_offset_asCcOffset_asCcLen, 0);
			if (asn == -1) return false;
			asn &= 0xFFFF_FFFFL;
			offset = asn_cidrMask_offset_asCcOffset_asCcLen[2];

			final int ipResponseOffset = offset;
			// noinspection StatementWithEmptyBody
			while (response[offset++] != '/') {
			}
			asn_cidrMask_offset_asCcOffset_asCcLen[2] = offset;
			long cidrMask = readShortUntilPipe(response, length, asn_cidrMask_offset_asCcOffset_asCcLen, -1);
			if (cidrMask == -1) return false;
			final int ipResponseLen = offset - ipResponseOffset + (int) (cidrMask >>> 32);
			cidrMask &= 0xFFFF_FFFFL;
			offset = asn_cidrMask_offset_asCcOffset_asCcLen[2];

			final int countryCodeResponseOffset = offset;
			while (response[offset] != ' ' && response[offset] != '|') ++offset;
			// TODO Should we do checks like countryCodeResponseLen==2 ?
			//  ISO-3166 has a variant of 3 characters (https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes)
			final int countryCodeResponseLen = offset - countryCodeResponseOffset;

			final Level logLevel = Level.FINE;
			if (LOGGER.isLoggable(logLevel)) LOGGER.log(
				logLevel, "DNS response of IP->ASN (" + new String(
					// TODO Is it really UTF-8?
					response, ipResponseOffset, ipResponseLen, StandardCharsets.UTF_8) + " -> " + asn + ")");

			final int prevCidrMask = asn_cidrMask_offset_asCcOffset_asCcLen[1];
			if (cidrMask > prevCidrMask) {
				asn_cidrMask_offset_asCcOffset_asCcLen[0] = (int) asn;
				asn_cidrMask_offset_asCcOffset_asCcLen[1] = (int) cidrMask;
				asn_cidrMask_offset_asCcOffset_asCcLen[3] = countryCodeResponseOffset;
				asn_cidrMask_offset_asCcOffset_asCcLen[4] = countryCodeResponseLen;
			} else if (cidrMask == prevCidrMask && asn < asn_cidrMask_offset_asCcOffset_asCcLen[0]) {
				// If an ip has multiple ASNs associated with it (which should be impossible,
				// but in reality it may occur), just set the info associated with the lowest ASN
				asn_cidrMask_offset_asCcOffset_asCcLen[0] = (int) asn;
				asn_cidrMask_offset_asCcOffset_asCcLen[3] = countryCodeResponseOffset;
				asn_cidrMask_offset_asCcOffset_asCcLen[4] = countryCodeResponseLen;
			}

			offset = endOfAnswer;
			return true;
		} finally {
			asn_cidrMask_offset_asCcOffset_asCcLen[2] = offset;
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
		StringBuilder b = new StringBuilder("Received unexpected message (will get ignored, errno=")
			.append(errno)
			.append("): ");

		if (length == 0) {
			b.append("[]");
		} else {
			b.ensureCapacity(b.capacity() + 2 + 6 * length);
			b.append('[');
			int last = length - 1;
			for (int i = 0; i < last; ++i) b.append(response[i]).append(", ");
			b.append(response[last]).append(']');
		}

		LOGGER.warning(b.toString());
	}

	@Override
	public @Nullable AS ip2asn(InetAddress ip) {
		byte[] ipAddress = ip.getAddress();
		boolean isIPV6 = ip instanceof Inet6Address;
		int whoisHostOffset = 12 + (isIPV6 ? 64 : ipv4EncodingLength(ipAddress));
		byte[] whoisHost = isIPV6 ? whoisHostV6 : whoisHostV4;
		byte[] req = new byte[whoisHostOffset + whoisHost.length + 5];

		int id = this.id.getAndIncrement() & 0xFFFF;
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


		// Using a ThreadLocal instead of allocating memory is about 15% faster when the array is this big
		final byte[] response = UdpDigWhoisClient.response.get();

		requesters[id] = Thread.currentThread();
		BYTE_ARR_ARR_HANDLE.setVolatile(requesterBufs, id, response);
		DatagramPacket udpPacket = new DatagramPacket(req, req.length);
		udpPacket.setPort(port);
		int udpTries = 3;

		fetch:
		do {
			// Set flag to wait in park-loop later
			response[THEORETICAL_UDP_LIMIT] = -1;

			final long until = System.currentTimeMillis() + timeoutMillis;
			// udpTries & 1, according to the order set in the constructor
			udpPacket.setAddress(hostDns[udpTries & 1]);
			try {
				socket.send(udpPacket);
			} catch (IOException ex) {
				LOGGER.log(Level.SEVERE, "Socket exception while sending data", ex);
				continue;
			}

			if (!isAlive) {
				requesters[id] = null;
				requesterBufs[id] = null;
				return null;
			}
			wakeupListeners();

			while ((byte) BYTE_ARR_HANDLE.getVolatile(response, THEORETICAL_UDP_LIMIT) != 0) {
				// The packet probably got lost
				if (System.currentTimeMillis() > until) continue fetch;
				LockSupport.parkUntil(until);
			}

			AS result = decode(response);
			if (result != null) {
				requesters[id] = null;
				requesterBufs[id] = null;
				return result;
			}
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
