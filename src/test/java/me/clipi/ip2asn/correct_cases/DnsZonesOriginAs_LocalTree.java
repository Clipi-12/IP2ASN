package me.clipi.ip2asn.correct_cases;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.TestRunner;
import me.clipi.ip2asn.provider.LocalLookUpTree;
import me.clipi.ip2asn.routeviews.DnsZonesOriginAs;
import org.junit.jupiter.api.Assertions;

@SuppressWarnings("NewClassNamingConvention")
public abstract class DnsZonesOriginAs_LocalTree extends TestRunner.TestGroup {
	public DnsZonesOriginAs_LocalTree(boolean ipv6) {
		// TODO Check with exact matching
		super(AS::equals, DnsZonesOriginAs.class.getSimpleName() + ' ' + LocalLookUpTree.class.getSimpleName(),
			  ipv6,
			  () -> {
				  IIP2ASN res = TestRunner.getIp2asnMain();
				  Assertions.assertInstanceOf(LocalLookUpTree.class, res);
				  return res;
			  });
	}

	public static class IPv4 extends DnsZonesOriginAs_LocalTree {
		public IPv4() {
			super(false);
		}
	}

	public static class IPv6 extends DnsZonesOriginAs_LocalTree {
		public IPv6() {
			super(true);
		}
	}
}
