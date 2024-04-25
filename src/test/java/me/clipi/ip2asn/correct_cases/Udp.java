package me.clipi.ip2asn.correct_cases;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.TestRunner;
import me.clipi.ip2asn.provider.UdpDigWhoisClient;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;

@SuppressWarnings("NewClassNamingConvention")
public abstract class Udp extends TestRunner.TestGroup {
	public Udp(boolean ipv6) {
		super(AS::exactMatch, UdpDigWhoisClient.class.getSimpleName(), ipv6,
			  () -> {
				  IIP2ASN res = TestRunner.getIp2asnFallbacks()[0];
				  Assertions.assertInstanceOf(UdpDigWhoisClient.class, res);
				  return res;
			  });
	}

	@Disabled
	public static class IPv4 extends Udp {
		public IPv4() {
			super(false);
		}
	}

	@Disabled
	public static class IPv6 extends Udp {
		public IPv6() {
			super(true);
		}
	}
}
