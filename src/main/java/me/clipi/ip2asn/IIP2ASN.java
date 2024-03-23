package me.clipi.ip2asn;

import org.jetbrains.annotations.Nullable;

import java.net.InetAddress;

public interface IIP2ASN {
	@Nullable
	AS ip2asn(InetAddress ip);
}
