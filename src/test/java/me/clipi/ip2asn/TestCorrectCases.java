package me.clipi.ip2asn;

import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

public class TestCorrectCases {
	private static Map<InetAddress, AS> data;
	private static final IP2ASN ip2asn = new IP2ASN();
	private static final Level LOG_LEVEL = Level.parse(System.getProperty("me.clipi.testing.log_level", "INFO"));

	@AfterAll
	public static void cleanup() {
		ip2asn.close();
	}

	@BeforeAll
	public static void prepareData() throws IOException {
		BufferedReader file = new BufferedReader(new InputStreamReader(Objects.requireNonNull(
			TestCorrectCases.class.getClassLoader().getResourceAsStream("resources/asn-output.txt"))));
		// Ignore bulk msg
		file.readLine();

		LinkedHashMap<InetAddress, AS> data = new LinkedHashMap<>();

		file.lines()
			.parallel()
			.distinct()
			.map(line -> Arrays.stream(line.split("\\|"))
							   .map(String::trim)
							   .toArray(String[]::new))
			.forEachOrdered(info -> {
				InetAddress ip;
				try {
					ip = InetAddress.getByName(info[1]);
				} catch (UnknownHostException ex) {
					throw new RuntimeException(ex);
				}
				AS as = new AS(Integer.parseInt(info[0]), info[3]);
				synchronized (data) {
					data.merge(ip, as, (prevAs, newAs) -> {
						if (!Objects.equals(prevAs.countryCode(), newAs.countryCode())) throw new AssertionError();
						return newAs.asn() < prevAs.asn() ? newAs : prevAs;
					});
				}
			});

		TestCorrectCases.data = Collections.unmodifiableMap(data);
	}

	@BeforeAll
	public static void prepareLogging() {
		LogManager logManager = LogManager.getLogManager();
		logManager.getLoggerNames().asIterator().forEachRemaining(name -> {
			Logger logger = logManager.getLogger(name);
			if (logger == null) return;
			logger.setLevel(LOG_LEVEL);
			for (Handler handler : logger.getHandlers()) handler.setLevel(LOG_LEVEL);
		});
	}

	@TestFactory
	public DynamicContainer udpDigWhoisClient() {
		return testAllFetches("UDP-DIG-WHOIS", ip2asn.fallbackUdp);
	}

	private DynamicContainer testAllFetches(String testNamePrefix, @Nullable IIP2ASN ip2asn) {
		Assertions.assertNotNull(ip2asn);

		return dynamicContainer(
			testNamePrefix,
			data.entrySet()
				.parallelStream()
				.map(info -> dynamicTest(
					testNamePrefix + " test for ip " + info.getKey(),
					() -> {
						InetAddress ip = info.getKey();
						AS fetch = ip2asn.ip2asn(ip);
						Assertions.assertEquals(info.getValue(), fetch, ip::toString);
					})
				));
	}
}