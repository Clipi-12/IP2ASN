package me.clipi.ip2asn.routeviews;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IP2ASN;
import me.clipi.ip2asn.ip.IpRange;
import me.clipi.ip2asn.provider.LocalLookUpTree;
import me.clipi.ip2asn.util.FileCache;
import me.clipi.ip2asn.util.RuntimeIOException;
import org.itadaki.bzip2.BZip2InputStream;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DnsZonesOriginAs {
	private static final Logger LOGGER;

	static {
		// Initialize logger's parent
		// noinspection ResultOfMethodCallIgnored
		IP2ASN.class.getClass();
		LOGGER = Logger.getLogger("IP2ASN.DnsZonesOriginAs");
	}

	private DnsZonesOriginAs() {
	}

	private static final URL downloadUrl;

	static {
		try {
			downloadUrl = URI.create("http://ftp.routeviews.org/dnszones/originas.bz2").toURL();
		} catch (MalformedURLException ex) {
			throw new RuntimeException(ex);
		}
	}

	@Nullable
	private static LocalLookUpTree lookUpTree;

	public static LocalLookUpTree getInstance() throws IOException {
		if (lookUpTree != null) return lookUpTree;
		lookUpTree = LocalLookUpTree.createOrNull(FileCache.fromFileTimestamp(
			Path.of("ip2asn", "routeviews", "DnsZonesOriginAs"), "originas.bz2",
			downloadUrl, is -> {
				LocalLookUpTree.Ip2AsMapping ip2AsMapping = new LocalLookUpTree.Ip2AsMapping();
				try {
					//					new InputStreamSplit(new BZip2InputStream(is, false),
					//										 CodingErrorAction.REPORT, CodingErrorAction.REPORT, "\n")
					//						.parallelStream()
					Arrays.stream(new String(new BZip2InputStream(is, false).readAllBytes(), StandardCharsets.UTF_8).split("\n")).parallel()
						  .unordered()
						  .filter(s -> !s.isEmpty())
						  .map(line -> {
							  int i = line.indexOf(split1);
							  if (i < 0)
								  throw new IllegalArgumentException("Unexpected line: \"%s\"".formatted(line));
							  return line.substring(i + split1Len).trim();
						  })
						  .distinct()
						  .forEach(info -> parseEntry(info, ip2AsMapping));
				} catch (IllegalArgumentException ex) {
					LOGGER.log(Level.SEVERE, "Unexpected line while reading routeviews/dnszones/originas", ex);
					return null;
				} catch (RuntimeIOException ex) {
					throw ex.ioException;
				}
				return ip2AsMapping;
			}), Duration.ofMinutes(15), LOGGER);
		return lookUpTree;
	}


	private static final String split1 = "IN TXT", split2 = "\" \"";
	private static final int split1Len = split1.length(), split2Len = split2.length();

	private static void parseEntry(String info, LocalLookUpTree.Ip2AsMapping ip2AsMapping) throws IllegalArgumentException {
		final int lastIdx = info.length() - 1;
		if (info.charAt(0) != '"' || info.charAt(lastIdx) != '"')
			throw new IllegalArgumentException("Unexpected line: \"%s\"".formatted(info));
		int sep1 = info.indexOf(split2, 1);
		int sep2 = info.indexOf(split2, sep1 + split2Len);
		if (sep1 < 0 || sep2 < 0 || info.indexOf(split2, sep2 + split2Len) >= 0)
			throw new IllegalArgumentException("Unexpected line: \"%s\"".formatted(info));

		try {
			int asn;
			if (info.charAt(1) == '{') {
				if (info.charAt(sep1 - 1) != '}')
					throw new IllegalArgumentException("Unexpected line: \"%s\"".formatted(info));
				asn = Arrays.stream(info.substring(2, sep1 - 1).split(","))
							.mapToInt(Integer::parseUnsignedInt)
							.min()
							.orElseThrow();
			} else {
				asn = Integer.parseUnsignedInt(info.substring(1, sep1));
			}
			InetAddress start = InetAddress.getByName(
				info.substring(sep1 + split2Len, sep2));
			if (!(start instanceof Inet4Address start0))
				throw new IllegalArgumentException("Unexpected IP type " + start);
			int cidrSize = Integer.parseInt(info.substring(sep2 + split2Len, lastIdx));
			ip2AsMapping.ipv4.set(new IpRange<>(start0, cidrSize), new AS(asn, "XX"));
		} catch (NumberFormatException | UnknownHostException |
				 IndexOutOfBoundsException | NoSuchElementException ex) {
			throw new IllegalArgumentException(
				"Unexpected line: \"%s\"".formatted(info), ex);
		}
	}
}
