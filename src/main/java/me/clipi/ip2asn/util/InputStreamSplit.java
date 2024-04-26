package me.clipi.ip2asn.util;

import org.jetbrains.annotations.CheckReturnValue;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * A {@link String} {@code Spliterator} that takes an {@link InputStream} as input and divides it kind of like
 * {@link String#split(String)} does.
 *
 * @apiNote This implementation doesn't parse the delimiter as a regex {@link java.util.regex.Pattern}, and will
 * return an empty string as the last output if the input ends with the delimiter
 */
public class InputStreamSplit implements Spliterator<String> {
	private long estimateSize;
	private final InputStream input;

	public final @NotNull String delim;
	private final int delimLen;

	private boolean endOfStream;
	private StringSplit curr;

	static final int BUF_BYTES = 8192;
	private final CharsetDecoder charsetDecoder;
	private final byte[] buf = new byte[BUF_BYTES];
	private final ByteBuffer bufWrapper = ByteBuffer.wrap(buf);
	private CharBuffer charBuf = CharBuffer.allocate(BUF_BYTES << 3 /* arbitrary char buf size */);

	public InputStreamSplit(@NotNull InputStream input, @NotNull CodingErrorAction onMalformedInput,
							@NotNull CodingErrorAction onUnmappableCharacter, @NotNull String delim) {
		this(input, Long.MAX_VALUE, onMalformedInput, onUnmappableCharacter, delim);
	}

	public InputStreamSplit(@NotNull InputStream input, long estimateSize, @NotNull CodingErrorAction onMalformedInput,
							@NotNull CodingErrorAction onUnmappableCharacter, @NotNull String delim) {
		this.input = input;
		this.delim = delim;
		this.delimLen = delim.length();
		this.estimateSize = estimateSize != Long.MAX_VALUE ? (estimateSize << 2) / delimLen : Long.MAX_VALUE;
		charsetDecoder = StandardCharsets.UTF_8.newDecoder()
											   .onMalformedInput(onMalformedInput)
											   .onUnmappableCharacter(onUnmappableCharacter);
	}

	@Override
	public boolean tryAdvance(Consumer<? super String> action) throws RuntimeIOException {
		StringSplit curr = this.curr;
		if (curr != null && curr.tryAdvance(action)) return true;
		this.curr = null; // Notify it to trySplit()
		this.curr = curr = trySplit();
		if (curr == null) return false;
		boolean res = curr.tryAdvance(action);
		assert res;
		return true;
	}

	@Override
	public StringSplit trySplit() throws RuntimeIOException {
		if (curr != null) {
			StringSplit res = curr;
			curr = null;
			return res;
		}

		if (endOfStream) return null;

		final InputStream input = this.input;
		final byte[] buf = this.buf;
		final ByteBuffer bufWrapper = this.bufWrapper;

		CharBuffer charBuf = this.charBuf;
		do {
			final int bytesRead, offset = bufWrapper.position();
			{
				assert charBuf.limit() == charBuf.capacity();
				// UTF_8.averageBytesPerChar == 1. Using a bigger number
				// would make charBuf overflow more often
				final int remainingCharBufBytes = charBuf.remaining();
				if (remainingCharBufBytes == 0) charBuf = expand(charBuf);
				try {
					int available = input.available();
					bytesRead = input.read(buf, offset,
										   Math.min(
											   Math.min(BUF_BYTES - offset, remainingCharBufBytes),
											   available == 0 ? Integer.MAX_VALUE : available
										   )
					);
				} catch (IOException ex) {
					throw new RuntimeIOException(ex);
				}
			}

			if (bytesRead < 0) {
				endOfStream = true;
				charBuf = decode(bufWrapper, offset, charBuf);
				return returnSplit(charBuf, charBuf.limit());
			}

			if (bytesRead == 0) {
				Thread.yield();
				continue;
			}

			charBuf = decode(bufWrapper, bytesRead + offset, charBuf);

			int i = lastIndexOf(charBuf);
			if (i >= 0) return returnSplit(charBuf, i);
			// <editor-fold defaultstate="collapsed" desc="charBuf.inverseFlip();">
			final int newStart = charBuf.limit();
			charBuf.clear();
			charBuf.position(newStart);
			// </editor-fold>
		} while (true);
	}

	@SuppressWarnings("UnstableApiUsage")
	@CheckReturnValue
	private CharBuffer expand(@NotNull CharBuffer charBuf) {
		assert charBuf.limit() == charBuf.capacity();
		CharBuffer newBuf = CharBuffer.allocate(charBuf.capacity() << 1);
		newBuf.put(charBuf);
		this.charBuf = newBuf;
		return newBuf;
	}

	private CharBuffer decode(@NotNull ByteBuffer buf, int bytes, @NotNull CharBuffer charBuf) {
		assert charBuf.limit() == charBuf.capacity();

		buf.rewind();
		buf.limit(bytes);

		CoderResult res = charsetDecoder.decode(buf, charBuf, endOfStream);

		if (endOfStream) {
			if (res.isUnderflow()) res = charsetDecoder.flush(charBuf);
			charsetDecoder.reset();
		}
		if (res.isError()) {
			try {
				res.throwException();
			} catch (CharacterCodingException ex) {
				throw new RuntimeIOException(ex);
			}
			assert false;
		}

		charBuf.flip();
		buf.compact();
		if (res.isOverflow()) {
			CharBuffer newBuf = expand(charBuf);
			CharBuffer tryAgain = decode(buf, buf.limit(), charBuf);
			assert newBuf == tryAgain;
			return newBuf;
		}
		return charBuf;
	}

	private int lastIndexOf(final @NotNull CharBuffer charBuf) {
		assert charBuf.position() == 0;
		final int charBufLen = charBuf.limit();
		if (delimLen == 0) return charBufLen;
		if (charBufLen < delimLen) return -1;

		final String delim = this.delim;
		final int delimLastIdx = delimLen - 1;
		final char delimLast = delim.charAt(delimLastIdx);

		int i = charBufLen - 1;

		outer:
		do {
			while (i >= delimLastIdx && charBuf.get(i) != delimLast) --i;
			if (i < delimLastIdx) return -1;

			int j = i, k = delimLastIdx;
			while (k > 0) {
				if (charBuf.get(--j) != delim.charAt(--k)) {
					--i;
					continue outer;
				}
			}
			return i - delimLen + 1;
		} while (true);
	}

	private StringSplit returnSplit(@NotNull CharBuffer charBuf, int delimIndex) {
		String substring;
		{
			charBuf.rewind();
			int len = charBuf.limit();
			charBuf.limit(delimIndex);
			substring = charBuf.toString();
			int newStart = delimIndex + delimLen;
			if (newStart <= len) {
				charBuf.limit(len);
				charBuf.position(newStart);
				charBuf.compact();
			} else {
				assert endOfStream;
			}
		}

		long estimateSize = this.estimateSize;
		if (estimateSize != Long.MAX_VALUE && estimateSize != 0)
			this.estimateSize = Math.max(0, estimateSize - substring.length() / delimLen);
		return new StringSplit(substring, delim);
	}

	@Override
	public long estimateSize() {
		return estimateSize;
	}

	@Override
	public int characteristics() {
		return Spliterator.ORDERED | Spliterator.IMMUTABLE | Spliterator.NONNULL;
	}

	public Stream<String> parallelStream() {
		return stream(true);
	}

	public Stream<String> stream(boolean parallel) {
		return StreamSupport.stream(this, parallel);
	}
}
