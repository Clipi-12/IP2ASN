package me.clipi.ip2asn.util;

import org.jetbrains.annotations.NotNull;

import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * A {@link String} {@code Spliterator} that takes a {@link String} as input and divides it kind of like
 * {@link String#split(String)} does.
 *
 * @apiNote This implementation doesn't parse the delimiter as a regex {@link java.util.regex.Pattern}, and will
 * return an empty string as the last output if the input ends with the delimiter
 */
public class StringSplit implements Spliterator<String> {
	private final int endExclusive, delimLen;
	private int i;
	public final @NotNull String str, delim;


	public StringSplit(@NotNull String str, @NotNull String delim) {
		this(str, delim, 0, str.length());
	}

	private StringSplit(@NotNull String str, @NotNull String delim, int offset, int endExclusive) {
		this.str = str;
		this.delim = delim;
		this.delimLen = delim.length();
		this.i = offset;
		this.endExclusive = endExclusive;
	}

	@Override
	public boolean tryAdvance(Consumer<? super String> action) {
		int endExclusive = this.endExclusive;
		// The case i==endExclusive is deliberately not checked here since it represents that
		// the following string to be consumed is ""
		if (i > endExclusive) return false;
		int until = str.indexOf(delim, i);
		if (until < 0 || until >= endExclusive) {
			action.accept(str.substring(i, endExclusive));
			i = endExclusive + 1;
		} else {
			action.accept(str.substring(i, until));
			i = until + delimLen;
		}
		return true;
	}

	@Override
	public StringSplit trySplit() {
		final int curr = i, delimLen = this.delimLen, endExclusive = this.endExclusive;

		final int nextDelimStart;
		{
			final int nextDelimStart0 = str.indexOf(delim, (curr + endExclusive) >>> 1);
			nextDelimStart = nextDelimStart0 < 0 ? endExclusive : nextDelimStart0;
		}

		this.i = nextDelimStart + delimLen;
		return new StringSplit(str, delim, curr, Math.min(nextDelimStart, endExclusive + 1));
	}

	@Override
	public long estimateSize() {
		return Math.max((endExclusive - i) / delimLen + 1, 0);
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
