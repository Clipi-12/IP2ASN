package me.clipi.ip2asn.ip;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Supplier;

public final class CidrNode<IpType extends InetAddress, V> {
	private static final VarHandle childLowHandle, childHighHandle;

	static {
		try {
			MethodHandles.Lookup lu = MethodHandles.lookup();
			childLowHandle = lu.findVarHandle(CidrNode.class, "childLow", CidrNode.class);
			childHighHandle = lu.findVarHandle(CidrNode.class, "childHigh", CidrNode.class);
		} catch (ReflectiveOperationException ex) {
			throw new AssertionError(ex);
		}
	}

	private @Nullable CidrNode<IpType, V> childLow, childHigh;
	public final @Nullable CidrNode<IpType, V> parent;
	public final @NotNull IpRange<IpType> range;
	private @Nullable V value;
	private volatile boolean isSet;

	public boolean isRoot() {
		return range.cidrSize == 0;
	}

	@Nullable
	public V getDefaultValue() {
		return value;
	}

	@Nullable
	public V getInheritedValue() {
		return isSet ?
			value :
			parent == null ?
				null :
				parent.getInheritedValue();
	}

	public static <V> CidrNode<Inet4Address, V> newRootIpv4() {
		return new CidrNode<>(IpRange.IPV4_RANGE);
	}

	public static <V> CidrNode<Inet6Address, V> newRootIpv6() {
		return new CidrNode<>(IpRange.IPV6_RANGE);
	}

	private CidrNode(@NotNull IpRange<IpType> fullRange) {
		this.range = fullRange;
		this.parent = null;
		assert isRoot();
	}

	public CidrNode(@NotNull CidrNode<IpType, V> parent, @NotNull IpRange<IpType> range) {
		assert range.cidrSize > 0;
		assert range.cidrSize > parent.range.cidrSize;
		this.range = range;
		this.parent = parent;
	}

	private IpRange<IpType> genLowRange() {
		return new IpRange<>(range.getStart(), range.cidrSize + 1);
	}

	private IpRange<IpType> genHighRange() {
		int thisCidrSize = range.cidrSize;
		byte[] startHigh = range.getStartAsBytes();
		startHigh[thisCidrSize >>> 3] |= (byte) (0b1000_0000 >>> (thisCidrSize & 0x7));
		return new IpRange<>(range.toIpType(startHigh), thisCidrSize + 1);
	}

	private CidrNode<IpType, V> getOrGenLow() {
		return getOrGen(childLowHandle, this::genLowRange);
	}

	private CidrNode<IpType, V> getOrGenHigh() {
		return getOrGen(childHighHandle, this::genHighRange);
	}

	@SuppressWarnings("unchecked")
	private CidrNode<IpType, V> getOrGen(VarHandle child, Supplier<IpRange<IpType>> subRange) {
		CidrNode<IpType, V> res = (CidrNode<IpType, V>) child.getVolatile(this);
		if (res != null) return res;
		CidrNode<IpType, V> newChild = new CidrNode<>(this, subRange.get());
		res = (CidrNode<IpType, V>) child.compareAndExchange(this, null, newChild);
		return res == null ? newChild : res;
	}


	/**
	 * The {@link IpRange} represented by `start` and `cidrSize` has to be "inside"
	 * the range represented by `this.range`. It may represent the exact same range,
	 * in which case it should the new value has to equal the previous value as per
	 * {@link Objects#equals(Object, Object)}, unless it wasn't set previously, in
	 * which case it can be anything, including `null`.
	 *
	 * @param start    Start of the range to be set
	 * @param cidrSize cidrSize of the range to be set
	 * @throws IllegalArgumentException when trying to set two different values in the same range
	 */
	@SuppressWarnings("SynchronizationOnLocalVariableOrMethodParameter")
	void set(byte[] start, int cidrSize, @Nullable V value) throws IllegalArgumentException {
		assert start.length == range.ipTypeByteSize;
		CidrNode<IpType, V> node = this;
		assert cidrSize >= 0;
		assert cidrSize < range.ipTypeByteSize << 3;

		int thisCidrSize = node.range.cidrSize;
		do {
			assert cidrSize >= thisCidrSize;
			if (thisCidrSize == cidrSize) {
				assert Arrays.equals(node.range.getStartAsBytes(), start);
				synchronized (node) {
					V prev = node.value;
					if (node.isSet && !Objects.equals(prev, value))
						throw alreadyRegisteredRange(node.range, value, prev);
					node.value = value;
					node.isSet = true;
				}
				return;
			}

			node = (start[thisCidrSize >>> 3] & (0b1000_0000 >>> (thisCidrSize & 0x7))) == 0 ?
				node.getOrGenLow() : node.getOrGenHigh();
			++thisCidrSize;
			assert thisCidrSize == node.range.cidrSize;
		} while (true);
	}

	private static <IpType extends InetAddress, V> IllegalArgumentException alreadyRegisteredRange(
		IpRange<IpType> range, V newVal, V prev) {
		return new IllegalArgumentException(
			"Trying to register %s with the value %s failed because it was already registered with the value %s"
				.formatted(range, newVal, prev));
	}

	@SuppressWarnings("unchecked")
	public @NotNull CidrNode<IpType, V> get(@NotNull IpType key) {
		BigInteger key0 = new BigInteger(1, key.getAddress());
		CidrNode<IpType, V> node = this;

		do {
			assert key0.compareTo(node.range.start) >= 0;
			assert key0.compareTo(node.range.endInclusive) <= 0;

			CidrNode<IpType, V> low = (CidrNode<IpType, V>) childLowHandle.getVolatile(node);
			if (low != null) {
				if (key0.compareTo(low.range.endInclusive) <= 0) {
					node = low;
					continue;
				} else {
					CidrNode<IpType, V> high = (CidrNode<IpType, V>) childHighHandle.getVolatile(node);
					if (high != null) {
						node = high;
						continue;
					}
				}
			} else {
				CidrNode<IpType, V> high = (CidrNode<IpType, V>) childHighHandle.getVolatile(node);
				if (high != null && key0.compareTo(high.range.start) >= 0) {
					node = high;
					continue;
				}
			}

			return node;
		} while (true);
	}

	public TreeMap<IpRange<IpType>, @NotNull V> flatEntries() {
		TreeMap<IpRange<IpType>, @NotNull V> res = new TreeMap<>(IpTree.ipRangeStartComparator);
		flatEntries(res);

		// Assert keys don't overlap
		assert res.keySet().stream().skip(1).allMatch(k -> k.start.compareTo(res.lowerKey(k).endInclusive) > 0);

		return res;
	}

	@SuppressWarnings("unchecked")
	private void flatEntries(final TreeMap<IpRange<IpType>, @NotNull V> res) {
		CidrNode<IpType, V> low = (CidrNode<IpType, V>) childLowHandle.getVolatile(this);
		CidrNode<IpType, V> high = (CidrNode<IpType, V>) childHighHandle.getVolatile(this);

		V val = getInheritedValue();
		if (low == null && high == null) {
			if (val != null) res.put(range, val);
			return;
		}

		if (low == null) {
			high.flatEntries(res);
			if (val == null) return;

			V highVal = res.get(high.range);
			if (val.equals(highVal)) {
				// This could be avoided if we could use TreeMap.getEntry
				// instead of TreeMap.get, but this is a cold path anyway.
				// Also, the choice of using ceilingEntry or floorEntry is
				// arbitrary, since we know this is key exists
				IpRange<IpType> firstHighRange = res.ceilingEntry(high.range).getKey();
				assert firstHighRange.start.equals(high.range.start);

				res.remove(firstHighRange);
				res.put(new IpRange<>(range.start, firstHighRange.endInclusive, range.ipTypeByteSize), val);
			} else {
				res.put(genLowRange(), val);
			}

			return;
		}

		low.flatEntries(res);
		if (high == null) {
			if (val == null) return;

			IpRange<IpType> highRange = genHighRange();

			Map.Entry<IpRange<IpType>, @NotNull V> lowEntry = res.lowerEntry(highRange);
			if (lowEntry != null && val.equals(lowEntry.getValue())) {
				// Unfortunately we have to remove it even when we are going to put a value in the "same" key,
				// since the key is actually different even though the comparator says otherwise
				res.remove(lowEntry.getKey());
				res.put(new IpRange<>(lowEntry.getKey().start, range.endInclusive, range.ipTypeByteSize), val);
			} else {
				res.put(highRange, val);
			}

			return;
		}

		IpRange<IpType> lastLowKey;
		V lastLowValue;
		{
			Map.Entry<IpRange<IpType>, @NotNull V> lastLow = res.lowerEntry(high.range);
			lastLowKey = lastLow == null ? null : lastLow.getKey();
			lastLowValue = lastLow == null ? null : lastLow.getValue();
		}

		high.flatEntries(res);

		if (Objects.equals(lastLowValue, res.get(high.range)) && lastLowKey.endInclusive.add(BigInteger.ONE).equals(high.range.start)) {
			// The comments above also are applicable here
			res.remove(lastLowKey);
			IpRange<IpType> firstHighRange = res.ceilingEntry(high.range).getKey();
			assert firstHighRange.start.equals(high.range.start);
			res.remove(firstHighRange);

			res.put(new IpRange<>(lastLowKey.start, firstHighRange.endInclusive, range.ipTypeByteSize), lastLowValue);
		}
	}
}
