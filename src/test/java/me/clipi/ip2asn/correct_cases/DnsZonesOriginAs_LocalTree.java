package me.clipi.ip2asn.correct_cases;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.TestRunner;
import me.clipi.ip2asn.provider.LocalLookUpTree;
import me.clipi.ip2asn.routeviews.DnsZonesOriginAs;
import org.junit.jupiter.api.Assertions;

@SuppressWarnings("NewClassNamingConvention")
public class DnsZonesOriginAs_LocalTree extends TestRunner.TestGroup {
	public DnsZonesOriginAs_LocalTree() {
		super(AS::equals, DnsZonesOriginAs.class.getSimpleName() + ' ' + LocalLookUpTree.class.getSimpleName(),
			  false,
			  () -> {
				  IIP2ASN res = TestRunner.getIp2asnMain();
				  Assertions.assertInstanceOf(LocalLookUpTree.class, res);
				  return res;
			  });
	}
}
