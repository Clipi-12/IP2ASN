package me.clipi.ip2asn;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestPlan;
import org.opentest4j.AssertionFailedError;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Map;
import java.util.function.BiPredicate;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.DynamicTest.dynamicTest;

public class TestRunner implements TestExecutionListener {
	private static final Logger LOGGER = Logger.getLogger(TestRunner.class.getSimpleName());

	static Map<Inet4Address, AS> ipv4Data;
	static Map<Inet6Address, AS> ipv6Data;
	private static IP2ASN ip2asn;

	@SneakyThrows
	private static synchronized void ensureData() {
		if (ip2asn != null) return;
		prepareIp2Asn();
		DataSupplier.prepareData();
	}

	public static IIP2ASN getIp2asnMain() {
		ensureData();
		return ip2asn.main;
	}

	public static IIP2ASN[] getIp2asnFallbacks() {
		ensureData();
		return ip2asn.fallbacks;
	}

	private static final Level LOG_LEVEL = Level.parse(System.getProperty("me.clipi.testing.log_level", "INFO"));


	private static void prepareLogging() {
		LogManager logManager = LogManager.getLogManager();
		logManager.getLoggerNames().asIterator().forEachRemaining(name -> {
			Logger logger = logManager.getLogger(name);
			if (logger != null) logger.setLevel(LOG_LEVEL);
		});
	}

	private static void prepareIp2Asn() {
		LOGGER.info("Creating an IP2ASN instance...");
		long start = System.currentTimeMillis();
		ip2asn = IP2ASN.createDefault();
		LOGGER.info("IP2ASN instance created in %.2f seconds".formatted((System.currentTimeMillis() - start) / 1000f));
		System.gc();

		Assertions.assertNotNull(ip2asn);
		Assertions.assertEquals(2, ip2asn.fallbacks.length);
	}

	@SneakyThrows
	@Override
	public void testPlanExecutionStarted(TestPlan testPlan) {
		prepareLogging();
	}

	@Override
	public void testPlanExecutionFinished(TestPlan testPlan) {
		if (ip2asn != null) ip2asn.close();
	}

	public static abstract class TestGroup {
		private final BiPredicate<AS, AS> equality;
		private final String testNamePrefix;
		private final Supplier<IIP2ASN> ip2asn;
		private final boolean ipv6;

		protected TestGroup(BiPredicate<AS, AS> equality, String testNamePrefix, boolean ipv6,
							Supplier<IIP2ASN> ip2asn) {
			this.equality = equality;
			this.testNamePrefix = (ipv6 ? "IPv6 - " : "IPv4 - ") + testNamePrefix;
			this.ip2asn = ip2asn;
			this.ipv6 = ipv6;
		}

		@TestFactory
		public Stream<DynamicTest> performTests() {
			final IIP2ASN ip2asn = this.ip2asn.get();
			Assertions.assertNotNull(ip2asn);

			final BiPredicate<AS, AS> equality = this.equality;

			return (ipv6 ? ipv6Data : ipv4Data)
				.entrySet()
				.parallelStream()
				.map(info -> dynamicTest(
					testNamePrefix + " test for ip " + info.getKey().getHostAddress(),
					() -> {
						InetAddress ip = info.getKey();
						AS expected = info.getValue();
						AS fetch = ip2asn.ip2asn(ip);
						if (!equality.test(expected, fetch)) throw new AssertionFailedError(
							"%s ==> expected: <%s> but was: <%s>".formatted(ip.getHostAddress(), expected, fetch),
							expected, fetch
						);
					})
				);
		}
	}
}