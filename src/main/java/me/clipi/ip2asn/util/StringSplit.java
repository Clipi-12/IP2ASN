package me.clipi.ip2asn.util;

import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class StringSplit implements Spliterator<String> {
	private final int endExclusive, delimLen;
	private int i;
	public final String str, delim;


	public StringSplit(String str, String delim) {
		this(str, delim, 0, str.length());
	}

	private StringSplit(String str, String delim, int offset, int endExclusive) {
		this.str = str;
		this.delim = delim;
		this.delimLen = delim.length();
		this.i = offset;
		this.endExclusive = endExclusive;
	}

	@Override
	public boolean tryAdvance(Consumer<? super String> action) {
		if (i >= endExclusive) return false;
		int until = str.indexOf(delim, i);
		if (until < 0) {
			action.accept(str.substring(i));
			this.i = endExclusive;
		} else {
			action.accept(str.substring(i, until));
			this.i = until + delimLen;
		}
		return true;
	}

	@Override
	public Spliterator<String> trySplit() {
		int curr = i;
		int delimLen = this.delimLen;
		int i = this.i = str.indexOf(delim, (curr + endExclusive) >>> 1) + delimLen;
		if (i < delimLen) {
			this.i = endExclusive;
			return null;
		}
		return new StringSplit(str, delim, curr, i - delimLen);
	}

	@Override
	public long estimateSize() {
		return endExclusive - i;
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
