package me.clipi.ip2asn.util;

import me.clipi.ip2asn.IP2ASN;
import me.clipi.ip2asn.util.function.CheckedFunction;
import me.clipi.ip2asn.util.function.CheckedSupplier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class FileCache<Out> {
	private static final Logger LOGGER;

	static {
		// Initialize logger's parent
		// noinspection ResultOfMethodCallIgnored
		IP2ASN.class.getClass();
		LOGGER = Logger.getLogger("IP2ASN.FileCache");
	}

	private static final Path parentDir;

	static {
		try {
			File jarFolder = new File(FileCache.class.getProtectionDomain()
													 .getCodeSource()
													 .getLocation()
													 .toURI()).getParentFile();
			parentDir = (jarFolder.exists() ? jarFolder.toPath() : Files.createTempDirectory(null));
		} catch (IOException | URISyntaxException ex) {
			throw new RuntimeException(ex);
		}
	}

	private final Path staleCheckFile, dataFile;
	private final CheckedFunction<InputStream, Out, IOException> generateData;
	private final CheckedSupplier<InputStream, IOException> downloadData;
	private final CheckedSupplier<byte[], IOException> timestampGenerator;
	private byte[] timestamp;
	private boolean readFromFile;

	public static <Out> FileCache<Out> fromFileTimestamp(Path dir, String dataFileName, URL url,
														 CheckedFunction<@NotNull InputStream, Out, IOException> generateData) throws IOException {
		return new FileCache<>(dir, dataFileName, generateData, url::openStream, () -> {
			URLConnection conn = url.openConnection();
			try (InputStream _connectionCloser = conn.getInputStream()) {
				long timestamp = conn.getLastModified();
				return new byte[] {
					(byte) (timestamp >>> 56),
					(byte) (timestamp >>> 48),
					(byte) (timestamp >>> 40),
					(byte) (timestamp >>> 32),
					(byte) (timestamp >>> 24),
					(byte) (timestamp >>> 16),
					(byte) (timestamp >>> 8),
					(byte) (timestamp)
				};
			}
		});
	}

	public FileCache(Path dir, String dataFileName,
					 CheckedFunction<@NotNull InputStream, Out, IOException> generateData,
					 CheckedSupplier<@NotNull InputStream, IOException> downloadData,
					 CheckedSupplier<byte @NotNull [], IOException> timestampGenerator) throws IOException {
		Path folder = parentDir.resolve(dir);
		Files.createDirectories(folder);
		this.staleCheckFile = folder.resolve("staleCheck.bin");
		this.dataFile = folder.resolve(dataFileName);
		this.generateData = generateData;
		this.downloadData = downloadData;
		this.timestampGenerator = timestampGenerator;

		if (Files.exists(staleCheckFile)) timestamp = Files.readAllBytes(staleCheckFile);
		readFromFile = Files.exists(dataFile) & !isStale();
	}

	public boolean isStale() {
		byte[] prev = timestamp;
		boolean stale;
		try {
			byte[] curr = timestamp = timestampGenerator.get();
			stale = prev == null || !Arrays.equals(prev, curr);
			if (stale) {
				LOGGER.fine(dataFile + " cache miss");
				readFromFile = false;
				Files.write(staleCheckFile, curr);
			} else {
				LOGGER.fine(dataFile + " cache hit");
			}
		} catch (IOException ex) {
			LOGGER.log(Level.SEVERE, "IO exception while checking for stale data", ex);
			readFromFile = false;
			stale = true;
		}
		return stale;
	}

	@Nullable
	public Out generate() {
		try (InputStream is = readFromFile ?
			new BufferedInputStream(Files.newInputStream(dataFile)) :
			new FileTeeInputStream(downloadData.get(), dataFile)
		) {
			readFromFile = false;
			return generateData.apply(is);
		} catch (IOException ex) {
			LOGGER.log(Level.SEVERE, "IO exception while refreshing data input", ex);
			try {
				Files.deleteIfExists(dataFile);
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "IO exception while deleting stale data", e);
			}
			return null;
		}
	}

	private static class FileTeeInputStream extends InputStream {
		private final InputStream is;
		private final OutputStream os;

		protected FileTeeInputStream(InputStream is, Path file) throws IOException {
			LOGGER.fine("Caching data in " + file);
			this.is = is;
			this.os = Files.newOutputStream(file);
		}

		@Override
		public int read() throws IOException {
			synchronized (os) {
				int read = is.read();
				if (read >= 0) os.write(read);
				return read;
			}
		}

		@Override
		public int read(byte @NotNull [] b) throws IOException {
			synchronized (os) {
				int read = is.read(b);
				if (read > 0) os.write(b, 0, read);
				return read;
			}
		}

		@Override
		public int read(byte @NotNull [] b, int off, int len) throws IOException {
			synchronized (os) {
				int read = is.read(b, off, len);
				if (read > 0) os.write(b, off, read);
				return read;
			}
		}

		@Override
		public long skip(long n) throws IOException {
			synchronized (os) {
				return is.skip(n);
			}
		}

		@Override
		public int available() throws IOException {
			synchronized (os) {
				return is.available();
			}
		}

		@Override
		public void close() throws IOException {
			synchronized (os) {
				is.close();
				os.close();
			}
		}
	}
}
