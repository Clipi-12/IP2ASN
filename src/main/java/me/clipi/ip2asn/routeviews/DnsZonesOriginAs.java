package me.clipi.ip2asn.routeviews;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IP2ASN;
import me.clipi.ip2asn.ip.IpRange;
import me.clipi.ip2asn.provider.LocalLookUpTree;
import me.clipi.ip2asn.util.FileCache;
import me.clipi.ip2asn.util.StringSplit;
import org.itadaki.bzip2.BZip2InputStream;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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

	private static final Path staleCheck, data;

	static {
		try {
			File jarFolder = new File(DnsZonesOriginAs.class.getProtectionDomain()
															.getCodeSource()
															.getLocation()
															.toURI()).getParentFile();
			Path folder = (jarFolder.exists() ? jarFolder.toPath() : Files.createTempDirectory(null))
				.resolve(Path.of("ip2asn", "routeviews", "DnsZonesOriginAs"));
			staleCheck = folder.resolve("staleCheck.bin");
			data = folder.resolve("originas.bz2");
		} catch (IOException | URISyntaxException ex) {
			throw new RuntimeException(ex);
		}
	}

	@Nullable
	private static LocalLookUpTree lookUpTree;

	public static LocalLookUpTree getInstance() {
		if (lookUpTree == null) {
			CharsetDecoder charsetDecoder = StandardCharsets.UTF_8.newDecoder()
																  .onMalformedInput(CodingErrorAction.REPORT)
																  .onUnmappableCharacter(CodingErrorAction.REPORT);
			try {
				lookUpTree = LocalLookUpTree.createOrNull(FileCache.fromFileTimestamp(
					Path.of("ip2asn", "routeviews", "DnsZonesOriginAs"), "originas.bz2",
					URI.create("ftp://ftp.routeviews.org/dnszones/originas.bz2").toURL(), is0 -> {
						final BZip2InputStream is = new BZip2InputStream(is0, false);
						String str;
						try {
							// Temp solution
							str = charsetDecoder.decode(ByteBuffer.wrap(is.readAllBytes())).toString();
						} catch (CharacterCodingException ex) {
							LOGGER.log(Level.SEVERE, "Unexpected byte while reading routeviews/dnszones/originas", ex);
							return null;
						}

						LocalLookUpTree.Ip2AsMapping ip2AsMapping = new LocalLookUpTree.Ip2AsMapping();
						final String sep = "\" \"";
						final int sepLen = sep.length();
						try {
							new StringSplit(str, "\n")
								.parallelStream()
								.map(line -> {
									final String split = "IN TXT";
									int i = line.indexOf(split);
									if (i < 0) throw new IllegalArgumentException(line);
									return line.substring(i + split.length()).trim();
								})
								.unordered()
								.distinct()
								.forEach(info -> {
									final int lastIdx = info.length() - 1;
									if (info.charAt(0) != '"' || info.charAt(lastIdx) != '"')
										throw new IllegalArgumentException(info);
									int sep1 = info.indexOf(sep, 1);
									int sep2 = info.indexOf(sep, sep1 + sepLen);
									if (sep1 < 0 || sep2 < 0 || info.indexOf(sep, sep2 + sepLen) >= 0)
										throw new IllegalArgumentException(info);

									try {
										int asn;
										if (info.charAt(1) == '{') {
											if (info.charAt(sep1 - 1) != '}') throw new IllegalArgumentException(info);
											asn = Arrays.stream(info.substring(2, sep1 - 1).split(","))
														.mapToInt(Integer::parseUnsignedInt)
														.min()
														.orElseThrow();
										} else {
											asn = Integer.parseUnsignedInt(info.substring(1, sep1));
										}
										InetAddress start = InetAddress.getByName(
											info.substring(sep1 + sepLen, sep2));
										if (!(start instanceof Inet4Address start0))
											throw new IllegalArgumentException();
										int cidrSize = Integer.parseInt(info.substring(sep2 + sepLen, lastIdx));
										ip2AsMapping.ipv4.set(new IpRange<>(start0, cidrSize),
															  new AS(asn, "XX" /* TODO */));
									} catch (NumberFormatException | UnknownHostException |
											 IndexOutOfBoundsException | NoSuchElementException ex) {
										throw new IllegalArgumentException(info, ex);
									}
								});
						} catch (IllegalArgumentException ex) {
							LOGGER.log(Level.SEVERE, "Unexpected line while reading routeviews/dnszones/originas", ex);
							return null;
						}
						return ip2AsMapping;
					}), Duration.ofMinutes(15) /* TODO */, LOGGER);
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
		return lookUpTree;
	}
}
