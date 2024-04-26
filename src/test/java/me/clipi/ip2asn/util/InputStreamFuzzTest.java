package me.clipi.ip2asn.util;

import me.clipi.ip2asn.util.UTF8Test.UTF8Character;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.RepeatedTest;
import org.opentest4j.AssertionFailedError;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.random.RandomGenerator;
import java.util.regex.Pattern;

public class InputStreamFuzzTest {

	@RepeatedTest(500)
	public void fuzzTest() throws Exception {
		Random rng = new Random();
		final long seed = rng.nextLong();
		rng.setSeed(seed);
		testWithRng(rng, seed);
	}

	public void testWithRng(@NotNull final RandomGenerator rng, final long seed) throws Exception {
		try {
			CharsetDecoder charsetDecoder = StandardCharsets.UTF_8.newDecoder()
																  .onMalformedInput(CodingErrorAction.REPORT)
																  .onUnmappableCharacter(CodingErrorAction.REPORT);

			final int stringSize = rng.nextInt(500, 10_000);
			ByteArrayOutputStream baos = new ByteArrayOutputStream(stringSize << 2);

			UTF8Character.chooseRandom(rng).writeRandom(baos, rng);
			byte[] separatorBytes = baos.toByteArray();
			String separator = charsetDecoder.decode(ByteBuffer.wrap(separatorBytes)).toString();
			Assertions.assertEquals(1, separator.codePointCount(0, separator.length()), "With RNG seed = " + seed);
			baos.reset();

			for (int i = 0; i < stringSize; ++i) {
				if (rng.nextDouble() < 0.5d / InputStreamSplit.BUF_BYTES) {
					baos.write(separatorBytes, 0, separatorBytes.length);
				} else {
					UTF8Character.chooseRandom(rng).writeRandom(baos, rng);
				}
			}
			String str = charsetDecoder.decode(ByteBuffer.wrap(baos.toByteArray()))
									   .toString();
			Assertions.assertEquals(stringSize, str.codePointCount(0, str.length()), "With RNG seed = " + seed);

			// String::split doesn't create an entry when the string ends with the separator
			while (str.endsWith(separator)) str = str.substring(0, str.length() - separator.length());

			Assertions.assertArrayEquals(
				str.split(Pattern.quote(separator)),
				new InputStreamSplit(new ThrottledInputStream(baos.toByteArray(), rng),
									 charsetDecoder.malformedInputAction(),
									 charsetDecoder.unmappableCharacterAction(),
									 separator)
					.parallelStream()
					.toArray(String[]::new),
				"With RNG seed = " + seed);
		} catch (AssertionFailedError ex) {
			throw ex;
		} catch (Throwable ex) {
			throw new Exception("Exception with RNG seed = " + seed, ex);
		}
	}

	private static class ThrottledInputStream extends FilterInputStream {
		private final RandomGenerator rng;

		private ThrottledInputStream(byte[] bytes, RandomGenerator rng) {
			super(new ByteArrayInputStream(bytes));
			this.rng = rng;
		}

		@Override
		public int available() throws IOException {
			return Math.min(
				super.available(),
				rng.nextFloat() < 0.1 ? 0 : rng.nextInt(InputStreamSplit.BUF_BYTES << 3)
			);
		}
	}
}
