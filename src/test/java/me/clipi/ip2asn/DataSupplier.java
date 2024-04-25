package me.clipi.ip2asn;

import org.junit.jupiter.api.Assertions;

import java.io.IOException;
import java.io.OutputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static me.clipi.ip2asn.IoUtils.*;

class DataSupplier {
	private static final Logger LOGGER = Logger.getLogger(DataSupplier.class.getSimpleName());

	private static String invokeNetcat(String command, byte[] stdinBytes) throws IOException, InterruptedException {
		Process p;
		try {
			p = new ProcessBuilder(command, "whois.cymru.com", "43")
				.redirectError(ProcessBuilder.Redirect.INHERIT)
				.start();
		} catch (IOException ex) {
			return null;
		}

		CountDownLatch closeStdin = new CountDownLatch(1);
		// Sending bytes to the process'`stdin` has to be done in a separate thread, as there may not be enough
		// buffer space in process'`stdout` (not the process'`stdin`), so reading the process'`stdout` bytes
		// _after_ sending _all_ the bytes may cause the VM to hang, as it will be waiting for someone to
		// receive data before sending more bytes
		new Thread(() -> {
			try (OutputStream stdin = p.getOutputStream()) {
				stdin.write(stdinBytes);
				stdin.flush();
				closeStdin.await();
			} catch (IOException | InterruptedException ex) {
				throw new RuntimeException(ex);
			}
		}).start();

		try {
			String result = isToString(p.getInputStream());
			closeStdin.countDown();
			return p.waitFor() == 0 ? result : null;
		} catch (Throwable ex) {
			p.destroyForcibly();
			throw ex;
		}
	}

	private static String cachedFiles(Path resources, Path cache, String file) throws IOException {
		boolean fileMatches = saveHashAndCheck(hash(file), resources.resolve("file-checksum.sha1"));

		final byte[][] checksumIPV4 = { null };
		final byte[][] checksumIPV6 = { null };
		fetch("https://github.com/T145/black-mirror/releases/download/latest/CHECKSUMS.txt")
			.lines()
			.parallel()
			.unordered()
			.forEach(line -> {
				byte[] bytes = line.substring(0, line.indexOf(' ')).getBytes(StandardCharsets.UTF_8);
				if (line.endsWith("BLOCK_IPV4.txt")) {
					assert checksumIPV4[0] == null;
					checksumIPV4[0] = bytes;
				} else if (line.endsWith("BLOCK_IPV6.txt")) {
					assert checksumIPV6[0] == null;
					checksumIPV6[0] = bytes;
				}
			});
		if (checksumIPV4[0] == null || checksumIPV6[0] == null) throw new AssertionError();
		boolean ipv4Matches = saveHashAndCheck(checksumIPV4[0], resources.resolve("ipv4-checksum.txt"));
		boolean ipv6Matches = saveHashAndCheck(checksumIPV6[0], resources.resolve("ipv6-checksum.txt"));

		if (fileMatches && ipv4Matches && ipv6Matches && Files.exists(cache)) return Files.readString(cache);
		return null;
	}

	private static String cacheNetcat(Path resources, String file) throws IOException, InterruptedException {
		Path cache = resources.resolve("asn-output.txt");
		{
			String cached = cachedFiles(resources, cache, file);
			if (cached != null) return cached;
		}

		LOGGER.info("Could not find cached values of testing resources. Downloading input for them...");

		final int RANDOM_LINES = 5_000;
		String[] ipv4 = getRandomLines(
			fetch("https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV4.txt"), RANDOM_LINES);
		String[] ipv6 = getRandomLines(
			fetch("https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV6.txt"), RANDOM_LINES);

		String ips = Stream.concat(file.lines(), Stream.concat(Arrays.stream(ipv4), Arrays.stream(ipv6)))
						   .parallel()
						   .unordered()
						   .distinct()
						   .filter(Predicate.not(String::isEmpty))
						   .collect(Collectors.joining("\r\n"));

		LOGGER.info("Generating AS info for " + ips.lines().count() + " IPs...");

		byte[] stdin =
			("begin\r\nnotruncate\r\ncountrycode\r\n\r\n" + ips + "\r\n\r\nend\r\n")
				.getBytes(StandardCharsets.US_ASCII);

		String output = invokeNetcat("netcat", stdin);
		if (output == null) output = invokeNetcat("ncat", stdin);
		if (output == null) throw new IllegalStateException("Install `netcat` or `ncat` to run the tests!");

		output = output.lines()
					   .parallel()
					   .skip(1)
					   .filter(line -> !line.startsWith("NA"))
					   .collect(Collectors.joining("\n"));

		if (output.contains("Error")) {
			LOGGER.severe("The following input contained lines that don't represent an IP:\n\n" + ips);
			throw new IllegalArgumentException("An illegal input caused the output to contain errors:\n\n" +
											   output.lines()
													 .filter(line -> line.contains("Error"))
													 .collect(Collectors.joining("\n")) + "\n\n");
		}

		LOGGER.info("AS info generated. Caching it...");

		Files.writeString(cache, output);

		return output;
	}

	static void prepareData() throws IOException, URISyntaxException, InterruptedException {
		Path resources = createDir("tests", "resources");

		String file = isToString(TestRunner.class.getClassLoader().getResourceAsStream("resources/ips.txt"));

		String output = cacheNetcat(resources, file);

		Map<InetAddress, AS> data = output.lines()
										  .parallel()
										  .distinct()
										  .map(line -> Arrays.stream(line.split("\\|"))
															 .map(String::trim)
															 .toArray(String[]::new))
										  .collect(Collectors.toMap(
											  info -> {
												  try {
													  return InetAddress.getByName(info[1]);
												  } catch (UnknownHostException ex) {
													  throw new RuntimeException(ex);
												  }
											  },
											  info -> new AS(Integer.parseInt(info[0]), info[2]),
											  (prevAs, newAs) -> newAs.asn() < prevAs.asn() ? newAs : prevAs
										  ));
		TestRunner.ipv4Data = Collections.unmodifiableMap(filter(data, Inet4Address.class));
		TestRunner.ipv6Data = Collections.unmodifiableMap(filter(data, Inet6Address.class));
		Assertions.assertEquals(data.size(), TestRunner.ipv4Data.size() + TestRunner.ipv6Data.size());
	}

	private static <K, V, K_Out extends K> Map<K_Out, V> filter(Map<K, V> map, Class<K_Out> klass) {
		return map.entrySet()
				  .stream()
				  .filter(e -> klass.isInstance(e.getKey()))
				  .collect(Collectors.toMap(e -> klass.cast(e.getKey()), Map.Entry::getValue));
	}
}
