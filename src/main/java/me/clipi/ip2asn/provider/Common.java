package me.clipi.ip2asn.provider;

import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

import static me.clipi.ip2asn.provider.Errno.*;

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

	static int skipUntilPastFirst(byte[] arr, int offset, int available, int length, char limit, int errno,
								  Logger LOGGER) {
		do {
			if (offset >= available) {
				Common.warnUnexpectedPacketReceived(LOGGER, arr, length, errno);
				return -1;
			}
		} while (arr[offset++] != limit);

		return offset;
	}

	static int skipUntilCurrentIs(byte[] arr, int offset, int available, int length, char limit, int errno,
								  Logger LOGGER) {
		do {
			if (offset >= available) {
				Common.warnUnexpectedPacketReceived(LOGGER, arr, length, errno);
				return -1;
			}
			if (arr[offset] == limit) break;
			++offset;
		} while (true);

		return offset;
	}

	static int skipUntilNoMoreSpace(byte[] arr, int offset, int available, int length, int errno, Logger LOGGER) {
		do {
			if (offset >= available) {
				Common.warnUnexpectedPacketReceived(LOGGER, arr, length, errno);
				return -1;
			}
			if (arr[offset] != ' ') break;
			++offset;
		} while (true);

		return offset;
	}

	static long readIntUntilPipe(byte[] response, int available, int length, int[] offset,
								 int maxExtraSpaceSeparatedNums, Logger LOGGER) {
		int offset0 = offset[0];
		int numByteLength = 0;
		long num = 0;
		do {
			if (offset0 >= available) {
				warnUnexpectedPacketReceived(LOGGER, response, length, COMMON_READ_UNTIL_PIPE_NUM_OOB);
				return -1;
			}
			int digit = response[offset0++] & 0xFF;
			if (digit == '|') break;
			if (digit == ' ') {
				final int firstSpace = offset0 - 1;
				while (offset0 < available && response[offset0] == ' ') ++offset0;
				if (offset0 >= available) {
					warnUnexpectedPacketReceived(LOGGER, response, length, COMMON_READ_UNTIL_PIPE_END_OOB);
					return -1;
				}
				if (response[offset0] == '|') {
					++offset0;
					break;
				}
				// If an ip has multiple ASNs associated with it (which should be impossible,
				// but in reality it may occur), just return the lowest ASN
				if (response[offset0] >= '0' && response[offset0] <= '9') {
					if (maxExtraSpaceSeparatedNums > 0) {
						offset[0] = offset0;
						long next = readIntUntilPipe(response, available, length, offset,
													 maxExtraSpaceSeparatedNums - 1,
													 LOGGER);
						if (next < 0) return -1;
						numByteLength += (int) (next >>> 32) + offset0 - firstSpace;
						return ((long) numByteLength << 32) | (num < next ? num : (int) next);
					}
					warnUnexpectedPacketReceived(LOGGER, response, length, COMMON_READ_UNTIL_PIPE_TOO_MUCH_RECURSION);
					return -1;
				}
				warnUnexpectedPacketReceived(LOGGER, response, length, COMMON_READ_UNTIL_PIPE_UNEXPECTED_AFTER_SPACE);
				return -1;
			}
			digit -= '0';
			if (digit < 0 || digit > 9) {
				warnUnexpectedPacketReceived(LOGGER, response, length, COMMON_READ_UNTIL_PIPE_NOT_DIGIT);
				return -1;
			}
			num *= 10;
			num += digit;
			++numByteLength;
			if (num > 0xFFFF_FFFFL) {
				warnUnexpectedPacketReceived(LOGGER, response, length, COMMON_READ_UNTIL_PIPE_NUM_DOESNT_FIT_IN_INT);
				return -1;
			}
		} while (true);
		while (offset0 < available && response[offset0] == ' ') ++offset0;
		offset[0] = offset0;
		return ((long) numByteLength << 32) | (int) num;
	}
}
