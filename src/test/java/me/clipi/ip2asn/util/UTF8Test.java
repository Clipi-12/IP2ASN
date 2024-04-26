package me.clipi.ip2asn.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.random.RandomGenerator;

public class UTF8Test {
	public static final int
		UNICODE_LAST_VALID_CODEPOINT = 0x10FFFF,
		UNICODE_BYTE_ORDER_MARK = 0xFEFF;

	public enum UTF8Character {
		ONE_BYTE(0x00, 0x7F),
		TWO_BYTE(0x80, 0x7FF),
		THREE_BYTE(0x800, 0xFFFF),
		FOUR_BYTE(0x10000, UNICODE_LAST_VALID_CODEPOINT);

		public final int firstCodePoint, codePoints;
		public static final int surrogates = Character.MAX_SURROGATE + 1 - Character.MIN_SURROGATE;

		UTF8Character(int firstCodePoint, int lastCodePoint) {
			this.firstCodePoint = firstCodePoint;
			this.codePoints = lastCodePoint + 1 - firstCodePoint;
		}

		public static UTF8Character chooseRandom(RandomGenerator rng) {
			return values()[rng.nextInt(4)];
		}

		public void writeRandom(ByteArrayOutputStream baos, RandomGenerator rng) {
			switch (this) {
				case ONE_BYTE, TWO_BYTE, FOUR_BYTE -> writeUnchecked(baos, rng.nextInt(codePoints) + firstCodePoint);
				case THREE_BYTE -> {
					// Suppress surrogates
					int n = rng.nextInt(codePoints - surrogates) + firstCodePoint;
					writeUnchecked(baos, n >= Character.MIN_SURROGATE ? n + surrogates : n);
				}
			}
		}

		private void writeUnchecked(ByteArrayOutputStream baos, int n) {
			// https://en.wikipedia.org/wiki/UTF-8#Encoding
			switch (this) {
				case ONE_BYTE -> baos.write(n & 0b0111_1111);
				case TWO_BYTE -> {
					baos.write(((n >>> 6) & 0b0001_1111) | 0b1100_0000);
					baos.write((n & 0b0011_1111) | 0b1000_0000);
				}
				case THREE_BYTE -> {
					baos.write(((n >>> 12) & 0b0000_1111) | 0b1110_0000);
					baos.write(((n >>> 6) & 0b0011_1111) | 0b1000_0000);
					baos.write((n & 0b0011_1111) | 0b1000_0000);
				}
				case FOUR_BYTE -> {
					baos.write(((n >>> 18) & 0b0000_0111) | 0b1111_0000);
					baos.write(((n >>> 12) & 0b0011_1111) | 0b1000_0000);
					baos.write(((n >>> 6) & 0b0011_1111) | 0b1000_0000);
					baos.write((n & 0b0011_1111) | 0b1000_0000);
				}
			}
		}

		public static int write(ByteArrayOutputStream baos, int n) {
			Assertions.assertTrue(n >= 0);
			Assertions.assertTrue(n <= UNICODE_LAST_VALID_CODEPOINT);
			if (n >= Character.MIN_SURROGATE && n <= Character.MAX_SURROGATE) return 0;

			if (n >= FOUR_BYTE.firstCodePoint) {
				FOUR_BYTE.writeUnchecked(baos, n);
				return 4;
			}
			if (n >= THREE_BYTE.firstCodePoint) {
				THREE_BYTE.writeUnchecked(baos, n);
				return 3;
			}
			if (n >= TWO_BYTE.firstCodePoint) {
				TWO_BYTE.writeUnchecked(baos, n);
				return 2;
			}
			ONE_BYTE.writeUnchecked(baos, n);
			return 1;
		}
	}


	@Test
	public void testUtf8Size() throws CharacterCodingException {
		final CharsetDecoder utf32Dec = Charset.forName("UTF-32").newDecoder()
											   .onMalformedInput(CodingErrorAction.REPORT)
											   .onUnmappableCharacter(CodingErrorAction.REPORT);
		final CharsetEncoder utf8Enc = StandardCharsets.UTF_8.newEncoder()
															 .onMalformedInput(CodingErrorAction.REPORT)
															 .onUnmappableCharacter(CodingErrorAction.REPORT);

		byte[] codePoint = new byte[4];
		ByteBuffer codePointWrapper = ByteBuffer.wrap(codePoint);
		for (int n = 0; n < UNICODE_LAST_VALID_CODEPOINT; ++n) {
			if (n >= Character.MIN_SURROGATE && n <= Character.MAX_SURROGATE || n == UNICODE_BYTE_ORDER_MARK)
				continue;

			// codePoint[0] = (byte) (n >>> 24); // Always 0
			codePoint[1] = (byte) (n >>> 16);
			codePoint[2] = (byte) (n >>> 8);
			codePoint[3] = (byte) (n);
			ByteBuffer asUtf8 = utf8Enc.encode(utf32Dec.decode(codePointWrapper));
			codePointWrapper.clear();
			if (n >= UTF8Character.FOUR_BYTE.firstCodePoint) {
				Assertions.assertEquals(4, asUtf8.limit());
			} else if (n >= UTF8Character.THREE_BYTE.firstCodePoint) {
				Assertions.assertEquals(3, asUtf8.limit());
			} else if (n >= UTF8Character.TWO_BYTE.firstCodePoint) {
				Assertions.assertEquals(2, asUtf8.limit());
			} else {
				Assertions.assertEquals(1, asUtf8.limit());
			}
		}
	}

	@Test
	public void testUtf8Equivalence() throws CharacterCodingException {
		final CharsetDecoder utf8Dec = StandardCharsets.UTF_8.newDecoder()
															 .onMalformedInput(CodingErrorAction.REPORT)
															 .onUnmappableCharacter(CodingErrorAction.REPORT);

		ByteArrayOutputStream out = new ByteArrayOutputStream(4);
		for (int n = 0; n < UNICODE_LAST_VALID_CODEPOINT; ++n) {
			if (n >= Character.MIN_SURROGATE && n <= Character.MAX_SURROGATE) continue;

			UTF8Character.write(out, n);
			String ch = utf8Dec.decode(ByteBuffer.wrap(out.toByteArray())).toString();
			out.reset();
			Assertions.assertEquals(1, ch.codePointCount(0, ch.length()));
			Assertions.assertEquals(n, ch.codePointAt(0));
		}
	}
}
