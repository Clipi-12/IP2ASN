package me.clipi.ip2asn.correct_cases;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.TestRunner;
import me.clipi.ip2asn.provider.TcpWhoisClient;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;

@SuppressWarnings("NewClassNamingConvention")
public abstract class Tcp extends TestRunner.TestGroup {
	public Tcp(boolean ipv6) {
		super(AS::exactMatch, TcpWhoisClient.class.getSimpleName(), ipv6,
			  () -> {
				  IIP2ASN res = TestRunner.getIp2asnFallbacks()[1];
				  Assertions.assertInstanceOf(TcpWhoisClient.class, res);
				  return res;
			  });
	}

	@Disabled
	public static class IPv4 extends Tcp {
		public IPv4() {
			super(false);
		}
	}

	@Disabled
	public static class IPv6 extends Tcp {
		public IPv6() {
			super(true);
		}
	}
}
