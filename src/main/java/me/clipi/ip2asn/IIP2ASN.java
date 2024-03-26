package me.clipi.ip2asn;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;

public interface IIP2ASN extends AutoCloseable {
	@Nullable
	AS ip2asn(@NotNull InetAddress ip);

	@Override
	void close();
}
