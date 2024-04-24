package me.clipi.ip2asn.util.function;

@FunctionalInterface
public interface CheckedFunction<T, R, E extends Throwable> {
	R apply(T t) throws E;
}
