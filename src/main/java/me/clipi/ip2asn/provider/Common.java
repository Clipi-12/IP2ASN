package me.clipi.ip2asn.provider;

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

class Common {
	private Common() {
	}

	private static final String WARN_HEAD = "Received unexpected message (part will get ignored, errno=";

	static void warnUnexpectedPacketReceived(Logger LOGGER, byte[] response, int length, int errno) {
		StringBuilder b = new StringBuilder(WARN_HEAD.length() + 10 + 7 * length);
		b.append(WARN_HEAD)
		 .append(errno)
		 .append("): ");

		if (length == 0) {
			b.append("[]");
		} else {
			b.append('[');
			int last = length - 1;
			for (int i = 0; i < last; ++i) b.append(response[i]).append(", ");
			b.append(response[last]).append(']').append('\n');
			b.append('"').append(new String(response, 0, length, StandardCharsets.US_ASCII)).append('"');
		}

		LOGGER.warning(b.toString());
	}

	static int skipUntilPastFirst(byte[] arr, int offset, int len, char limit, int errno, Logger LOGGER) {
		do {
			if (offset >= len) {
				Common.warnUnexpectedPacketReceived(LOGGER, arr, arr.length >= 0x0F_FF ? len : arr.length, errno);
				return -1;
			}
		} while (arr[offset++] != limit);

		return offset;
	}

	static int skipUntilCurrentIs(byte[] arr, int offset, int len, char limit, int errno, Logger LOGGER) {
		do {
			if (offset >= len) {
				Common.warnUnexpectedPacketReceived(LOGGER, arr, arr.length >= 0x0F_FF ? len : arr.length, errno);
				return -1;
			}
			if (arr[offset] == limit) break;
			++offset;
		} while (true);

		return offset;
	}

	static int skipUntilNoMoreSpace(byte[] arr, int offset, int len, int errno, Logger LOGGER) {
		do {
			if (offset >= len) {
				Common.warnUnexpectedPacketReceived(LOGGER, arr, arr.length >= 0x0F_FF ? len : arr.length, errno);
				return -1;
			}
			if (arr[offset] != ' ') break;
			++offset;
		} while (true);

		return offset;
	}

	static long readIntUntilPipe(byte[] response, int length, int[] offset, int recursion,
								 Logger LOGGER) {
		int offset0 = offset[0];
		int numByteLength = 0;
		int num = 0;
		do {
			if (offset0 >= length) {
				warnUnexpectedPacketReceived(LOGGER, response, length, 7);
				return -1;
			}
			int digit = response[offset0++] & 0xFF;
			if (digit == '|') break;
			if (digit == ' ') {
				final int firstSpace = offset0 - 1;
				while (offset0 < length && response[offset0] == ' ') ++offset0;
				if (offset0 >= length) {
					warnUnexpectedPacketReceived(LOGGER, response, length, 7);
					return -1;
				}
				if (response[offset0] == '|') {
					++offset0;
					break;
				}
				// If an ip has multiple ASNs associated with it (which should be impossible,
				// but in reality it may occur), just return the lowest ASN
				if (response[offset0] >= '0' && response[offset0] <= '9' && recursion >= 0 && recursion < 5) {
					offset[0] = offset0;
					long next = readIntUntilPipe(response, length, offset, recursion + 1, LOGGER);
					if (next < 0) return -1;
					numByteLength += (int) (next >>> 32) + offset0 - firstSpace;
					next &= 0xFFFF_FFFFL;
					return ((long) numByteLength << 32) | (num < next ? num : next);
				}
				warnUnexpectedPacketReceived(LOGGER, response, length, 7);
				return -1;
			}
			digit -= '0';
			if (digit < 0 || digit > 9) {
				warnUnexpectedPacketReceived(LOGGER, response, length, 6);
				return -1;
			}
			num *= 10;
			num += digit;
			++numByteLength;
		} while (true);
		while (offset0 < length && response[offset0] == ' ') ++offset0;
		offset[0] = offset0;
		return ((long) numByteLength << 32) | num;
	}
}
