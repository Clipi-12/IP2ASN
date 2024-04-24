package me.clipi.ip2asn.ip;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Comparator;
import java.util.TreeMap;

// TODO Test parsers that use entries that aren't represented with a CIDR block
public class IpTree<IpType extends InetAddress, V> {
	@SuppressWarnings("rawtypes")
	static final Comparator<IpRange> ipRangeStartComparator = Comparator.comparing(a -> a.start);
	public final @NotNull CidrNode<IpType, V> cidrRoot;

	public static <V> IpTree<Inet4Address, V> newIpv4Tree() {
		return new IpTree<>(CidrNode.newRootIpv4());
	}

	public static <V> IpTree<Inet6Address, V> newIpv6Tree() {
		return new IpTree<>(CidrNode.newRootIpv6());
	}

	private IpTree(CidrNode<IpType, V> cidrRoot) {
		assert cidrRoot.isRoot();
		this.cidrRoot = cidrRoot;
	}

	@Nullable
	public V get(IpType key) {
		return cidrRoot.get(key).getInheritedValue();
	}

	/**
	 * @throws IllegalArgumentException if part of the range was already registered and the conflicts
	 *                                  cannot be resolved
	 * @throws IllegalArgumentException if the key isn't a CIDR block and the value is null
	 */
	public void set(IpRange<IpType> key, V value) throws IllegalArgumentException {
		int cidrSize = key.cidrSize;
		if (cidrSize >= 0) {
			cidrRoot.set(key.getStartAsBytes(), cidrSize, value);
		}
	}

	@NotNull
	public TreeMap<IpRange<IpType>, @NotNull V> flatten() {
		return cidrRoot.flatEntries();
	}
}
