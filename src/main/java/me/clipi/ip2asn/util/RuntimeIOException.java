package me.clipi.ip2asn.util;

import java.io.IOException;

public class RuntimeIOException extends RuntimeException {
	public final IOException ioException;

	public RuntimeIOException(IOException ioException) {
		super(ioException);
		this.ioException = ioException;
	}
}
