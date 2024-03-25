package me.clipi.ip2asn;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class IoUtils {
	public static Path createDir(String first, String... more) throws URISyntaxException, IOException {
		return Files.createDirectories(
			Path.of(IoUtils.class.getProtectionDomain()
								 .getCodeSource()
								 .getLocation()
								 .toURI()
			).resolve(Path.of(first, more))
		);
	}

	public static String[] getRandomLines(String input, int n) {
		String[] lines = input.lines().parallel().unordered().toArray(String[]::new);
		n = Math.min(n, lines.length);
		String[] res = new String[n];
		Random r = new Random();
		for (int i = 0; i < n; ++i) res[i] = lines[r.nextInt(lines.length)];
		return res;
	}

	public static String fetch(String uri) throws IOException {
		return isToString(URI.create(uri).toURL().openStream());
	}

	public static String isToString(InputStream inputStream) throws IOException {
		if (inputStream == null) return "";
		try (InputStream inputStream0 = inputStream) {
			byte[] bytes = inputStream0.readAllBytes();
			return new String(bytes, StandardCharsets.UTF_8);
		}
	}

	public static byte[] hash(String str) {
		MessageDigest crypt;
		try {
			crypt = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException ex) {
			throw new AssertionError(ex);
		}
		crypt.reset();
		crypt.update(str.getBytes(StandardCharsets.UTF_8));
		return crypt.digest();
	}

	public static boolean saveHashAndCheck(byte[] actualHash, Path expectedHash) throws IOException {
		if (Files.exists(expectedHash)) {
			byte[] hashBytes = Files.readAllBytes(expectedHash);

			if (Arrays.equals(actualHash, hashBytes)) return true;
		}

		Files.write(expectedHash, actualHash);
		return false;
	}
}
