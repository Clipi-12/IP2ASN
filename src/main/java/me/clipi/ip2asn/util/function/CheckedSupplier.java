package me.clipi.ip2asn.util.function;

/**
 * Similar to Callable, but you can specify the exception type
 */
@FunctionalInterface
public interface CheckedSupplier<T, E extends Throwable> {
	T get() throws E;
}
