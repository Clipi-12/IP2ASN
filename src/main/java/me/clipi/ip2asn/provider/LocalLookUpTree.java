package me.clipi.ip2asn.provider;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.IP2ASN;
import me.clipi.ip2asn.ip.IpRange;
import me.clipi.ip2asn.ip.IpTree;
import me.clipi.ip2asn.util.FileCache;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LocalLookUpTree implements IIP2ASN {
	private static final Logger LOGGER;

	static {
		// Initialize logger's parent
		// noinspection ResultOfMethodCallIgnored
		IP2ASN.class.getClass();
		LOGGER = Logger.getLogger("IP2ASN.LocalLookUpTree");
	}

	public static class Ip2AsMapping {
		public final IpTree<Inet4Address, AS> ipv4 = IpTree.newIpv4Tree();
		public final IpTree<Inet6Address, AS> ipv6 = IpTree.newIpv6Tree();
	}

	private final FileCache<Ip2AsMapping> dataCache;
	private volatile AS[] ipv4AS, ipv6AS;
	private int[] ipv4StartRangeExcess2n1, ipv4EndInclusiveRangeExcess2n1;
	private long[] ipv6StartRangeHighExcess2n1, ipv6StartRangeLowExcess2n1,
		ipv6EndInclusiveRangeHighExcess2n1, ipv6EndInclusiveRangeLowExcess2n1;
	private volatile boolean isAlive = true;
	private final Thread periodicDataRefresher;

	@Override
	public void close() {
		isAlive = false;
		LockSupport.unpark(periodicDataRefresher);
	}

	@Nullable
	public static LocalLookUpTree createOrNull(FileCache<Ip2AsMapping> dataCache, Duration checkPeriod,
											   Logger LOGGER) {
		try {
			return new LocalLookUpTree(dataCache, checkPeriod);
		} catch (IllegalStateException ex) {
			LOGGER.log(Level.SEVERE, "Exception while creating LocalLookUpTree", ex);
			return null;
		}
	}

	public LocalLookUpTree(FileCache<Ip2AsMapping> dataCache, Duration checkPeriod) throws IllegalStateException {
		this.dataCache = dataCache;
		long checkPeriodMillis = checkPeriod.toMillis();

		periodicDataRefresher = new Thread(() -> {
			long until = System.currentTimeMillis() + checkPeriodMillis;
			do {
				LockSupport.parkUntil(until);
				if (!isAlive) break;
				long now = System.currentTimeMillis();
				if (now < until) continue;
				until = now + checkPeriodMillis;
				if (dataCache.isStale()) forceRefreshData();
			} while (true);
		}, "LocalLookUpTree-PeriodicDataRefresher");

		forceRefreshData();
		if (ipv4AS == null)
			throw new IllegalStateException("Data could not be fetched at the start of LocalLookUpTree");
		periodicDataRefresher.start();
	}

	private void forceRefreshData() {
		Ip2AsMapping ip2AsMapping = dataCache.generate();
		if (ip2AsMapping == null) {
			LOGGER.severe("Expected non null mapping... Maintaining stale data!");
			return;
		}

		Object[] ipv4 = genIpRange2As(int[]::new, ip -> {
			assert ip.bitLength() >>> 3 <= 4;
			return ip.intValue() ^ Integer.MIN_VALUE;
		}, ip2AsMapping.ipv4.flatten(), false);
		Object[] ipv6 = genIpRange2As(long[]::new, ip -> {
			assert ip.bitLength() >>> 3 <= 16;
			return new long[] {
				ip.shiftRight(64).longValue() ^ Long.MIN_VALUE,
				ip.longValue() ^ Long.MIN_VALUE
			};
		}, ip2AsMapping.ipv6.flatten(), true);

		ipv4AS = (AS[]) ipv4[0];
		ipv4StartRangeExcess2n1 = (int[]) ipv4[1];
		ipv4EndInclusiveRangeExcess2n1 = (int[]) ipv4[2];

		ipv6AS = (AS[]) ipv6[0];
		ipv6StartRangeHighExcess2n1 = (long[]) ipv6[1];
		ipv6EndInclusiveRangeHighExcess2n1 = (long[]) ipv6[2];
		ipv6StartRangeLowExcess2n1 = (long[]) ipv6[3];
		ipv6EndInclusiveRangeLowExcess2n1 = (long[]) ipv6[4];
	}

	private static <IpType extends InetAddress> Object[] genIpRange2As(IntFunction<Object> arrayGen,
																	   Function<BigInteger, Object> ip2Bytes,
																	   TreeMap<IpRange<IpType>, AS> ip2AsMapping,
																	   boolean twoArrays) {
		final int len = ip2AsMapping.size();
		AS[] as = new AS[len];
		Object startRange1 = arrayGen.apply(len), endInclusiveRange1 = arrayGen.apply(len);
		Object startRange2 = twoArrays ? arrayGen.apply(len) : null,
			endInclusiveRange2 = twoArrays ? arrayGen.apply(len) : null;

		int i = 0;
		for (Map.Entry<IpRange<IpType>, AS> ip2as : ip2AsMapping.entrySet()) {
			as[i] = ip2as.getValue();
			IpRange<IpType> range = ip2as.getKey();
			if (twoArrays) {
				Object start = ip2Bytes.apply(range.start);
				Object endInclusive = ip2Bytes.apply(range.start);
				Array.set(startRange1, i, Array.get(start, 0));
				Array.set(startRange2, i, Array.get(start, 1));
				Array.set(endInclusiveRange1, i, Array.get(endInclusive, 0));
				Array.set(endInclusiveRange2, i, Array.get(endInclusive, 1));
			} else {
				Array.set(startRange1, i, ip2Bytes.apply(range.start));
				Array.set(endInclusiveRange1, i, ip2Bytes.apply(range.endInclusive));
			}
			++i;
		}
		return new Object[] { as, startRange1, endInclusiveRange1, startRange2, endInclusiveRange2 };
	}

	@Override
	public @Nullable AS v4ip2asn(byte @NotNull [] ip) {
		assert ip.length == 4;
		if (!isAlive) return null;

		int ipExcess2n1 = Integer.MIN_VALUE ^ (
			(ip[0] & 0xFF) << 24 |
			(ip[1] & 0xFF) << 16 |
			(ip[2] & 0xFF) << 8 |
			(ip[3] & 0xFF));

		int[] start, endInclusive;
		AS[] as;
		do {
			as = ipv4AS;
			start = ipv4StartRangeExcess2n1;
			endInclusive = ipv4EndInclusiveRangeExcess2n1;
			if (as == ipv4AS) break;
			Thread.yield();
		} while (true);

		int left = 0;
		int right = start.length;

		while (left < right) {
			int m = (left + right) >>> 1;
			if (ipExcess2n1 < start[m]) {
				right = m;
			} else if (ipExcess2n1 > endInclusive[m]) {
				left = m + 1;
			} else {
				return as[m];
			}
		}

		return --right >= 0 && ipExcess2n1 >= start[right] && ipExcess2n1 <= endInclusive[right] ? as[right] : null;
	}

	@Override
	public @Nullable AS v6ip2asn(byte @NotNull [] ip) {
		assert ip.length == 16;
		if (!isAlive) return null;

		long ipHighExcess2n1 = Long.MIN_VALUE ^ (
			((ip[0] & 0xFFL) << 56) |
			((ip[1] & 0xFFL) << 48) |
			((ip[2] & 0xFFL) << 40) |
			((ip[3] & 0xFFL) << 32) |
			((ip[4] & 0xFFL) << 24) |
			((ip[5] & 0xFFL) << 16) |
			((ip[6] & 0xFFL) << 8) |
			((ip[7] & 0xFFL))
		);
		long ipLowExcess2n1 = Long.MIN_VALUE ^ (
			((ip[8] & 0xFFL) << 56) |
			((ip[9] & 0xFFL) << 48) |
			((ip[10] & 0xFFL) << 40) |
			((ip[11] & 0xFFL) << 32) |
			((ip[12] & 0xFFL) << 24) |
			((ip[13] & 0xFFL) << 16) |
			((ip[14] & 0xFFL) << 8) |
			((ip[15] & 0xFFL))
		);

		long[] startHigh, startLow, endInclusiveHigh, endInclusiveLow;
		AS[] as;
		do {
			as = ipv6AS;
			startHigh = ipv6StartRangeHighExcess2n1;
			startLow = ipv6StartRangeLowExcess2n1;
			endInclusiveHigh = ipv6EndInclusiveRangeHighExcess2n1;
			endInclusiveLow = ipv6EndInclusiveRangeLowExcess2n1;
			if (as == ipv6AS) break;
			Thread.yield();
		} while (true);

		int left = 0;
		int right = startHigh.length;

		while (left < right) {
			int m = (left + right) >>> 1;
			long startHigh_m = startHigh[m];
			if (ipHighExcess2n1 < startHigh_m || (ipHighExcess2n1 == startHigh_m && ipLowExcess2n1 < startLow[m])) {
				right = m;
			} else {
				long endInclusiveHigh_m = endInclusiveHigh[m];
				if (ipHighExcess2n1 > endInclusiveHigh_m || (ipHighExcess2n1 == endInclusiveHigh_m && ipLowExcess2n1 > endInclusiveLow[m])) {
					left = m + 1;
				} else {
					return as[m];
				}
			}
		}

		return --right >= 0 &&
			   (ipHighExcess2n1 > startHigh[right] || (ipHighExcess2n1 == startHigh[right] && ipLowExcess2n1 >= startLow[right])) &&
			   (ipHighExcess2n1 < endInclusiveHigh[right] || (ipHighExcess2n1 == endInclusiveHigh[right] && ipLowExcess2n1 <= endInclusiveLow[right])) ?
			as[right] : null;
	}
}
