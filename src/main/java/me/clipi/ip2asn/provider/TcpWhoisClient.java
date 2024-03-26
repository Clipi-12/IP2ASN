package me.clipi.ip2asn.provider;

import me.clipi.ip2asn.AS;
import me.clipi.ip2asn.IIP2ASN;
import me.clipi.ip2asn.IP2ASN;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TcpWhoisClient implements IIP2ASN {
	private static final Logger LOGGER;

	static {
		// Initialize logger's parent
		// noinspection ResultOfMethodCallIgnored
		IP2ASN.class.getClass();
		LOGGER = Logger.getLogger("IP2ASN.TcpWhoisClient");
	}


	private final InetAddress host;
	private final int port;
	private final long timeoutMillis;

	private static final int
		REQUEST_BULK_SIZE = 1 << 8,
		REQUEST_BULK_SIZE_M1 = REQUEST_BULK_SIZE - 1,
		TOTAL_REQUESTERS = REQUEST_BULK_SIZE << 8,
		TOTAL_REQUESTERS_M1 = TOTAL_REQUESTERS - 1;
	private final Thread[] requesters = new Thread[TOTAL_REQUESTERS];
	private final byte[][] buf = new byte[TOTAL_REQUESTERS][];
	private final AtomicInteger requestId = new AtomicInteger();


	private static final byte[]
		REQUEST_PROCESSING = new byte[0],
		REQUEST_RESERVED = new byte[0],
		REQUEST_UNWANTED = new byte[0];
	private static final VarHandle
		BYTE_ARR_HANDLE = MethodHandles.arrayElementVarHandle(byte[][].class);


	private final Thread periodicFlusher;
	private final AtomicLong periodicFlusherSleepUntil = new AtomicLong();
	private volatile boolean isAlive = true;

	@Override
	public void close() {
		isAlive = false;
		LockSupport.unpark(periodicFlusher);
	}

	public TcpWhoisClient(@NotNull InetAddress host, int port, long timeoutMillis) {
		this.host = host;
		this.port = port;
		this.timeoutMillis = timeoutMillis;
		periodicFlusher = new Thread(() -> {
			periodic_flush:
			while (isAlive) {
				{
					LockSupport.park();

					long sleepTime = periodicFlusherSleepUntil.get() - System.currentTimeMillis();
					if (sleepTime > 0) try {
						// noinspection BusyWait
						Thread.sleep(sleepTime);
					} catch (InterruptedException ignored) {
					}
				}

				int startId, currId, nextBlock, newId;
				do {
					currId = requestId.get();
					startId = currId & ~REQUEST_BULK_SIZE_M1;
					if (startId == currId) continue periodic_flush;
					nextBlock = startId + REQUEST_BULK_SIZE;
					// Set +1 because otherwise the next request would call flushRequests on "the previous bulk
					// buffer" (i.e. the buffer that we are going to flush right now)
					newId = (nextBlock | 1) & TOTAL_REQUESTERS_M1;
				} while (!requestId.compareAndSet(currId, newId));
				flushRequests(
					startId & TOTAL_REQUESTERS_M1,
					// Unfortunately we cannot flush according to the last used ID, but to the end of the block,
					// because if the compareAndSet in this::request that is responsible for avoiding "bulk-buffers"
					// that are being processed depends on the buffer being null at that ID. Therefore, we have to
					// ensure all the "bulk-buffer" is covered for this::flushRequests
					nextBlock & TOTAL_REQUESTERS_M1 /* currId & TOTAL_REQUESTERS_M1 */
				);
			}
		}, "TcpWhoisClient-PeriodicFlusher");
		periodicFlusher.start();
	}

	private static final byte[]
		HEADER = "begin\r\nnotruncate\r\ncountrycode\r\n".getBytes(StandardCharsets.US_ASCII),
		FOOTER = "end\r\n".getBytes(StandardCharsets.US_ASCII);

	private void flushRequests(final int start, final int end) {
		assert (start & REQUEST_BULK_SIZE_M1) == 0 : start + " is not at the start of a \"bulk-buffer\"";
		assert start < end : start + " >=" + end;

		final AtomicReference<byte[]> bulkRequest0 = new AtomicReference<>();
		final Socket socket;
		try {
			// noinspection resource
			socket = new Socket(host, port);
		} catch (IOException ex) {
			LOGGER.log(Level.SEVERE, "Exception while creating TCP socket", ex);
			return;
		}

		{
			// Fixed period of 250ms for the periodic flusher
			long prev, until = System.currentTimeMillis() + 250;
			do {
				prev = periodicFlusherSleepUntil.get();
			} while (until > prev && !periodicFlusherSleepUntil.compareAndSet(prev, until));
		}


		Thread auxIoThread = new Thread(() -> {
			byte[] bulkRequest;
			do {
				LockSupport.park();
				bulkRequest = bulkRequest0.get();
			} while (bulkRequest == null);

			int reqLen = ((bulkRequest[bulkRequest.length - 1] & 0xFF)) |
						 ((bulkRequest[bulkRequest.length - 2] & 0xFF) << 8) |
						 ((bulkRequest[bulkRequest.length - 3] & 0xFF) << 16) |
						 ((bulkRequest[bulkRequest.length - 4] & 0xFF) << 24);

			try {
				// TODO It would be nice if we knew bulkRequest.length at compile time so that we could call
				//  setSendBufferSize right after we _connect_ the socket. (notice _connect_, not create, in case we
				//  can reuse the socket)
				socket.setSendBufferSize(bulkRequest.length);

				OutputStream toServer = socket.getOutputStream();

				toServer.write(bulkRequest, 0, reqLen);
				toServer.flush();
			} catch (Exception ex) {
				LOGGER.log(Level.SEVERE, "TCP exception while sending data", ex);
			}
		}, "TcpWhoisClient-AuxIoThread-" + start + '-' + end);
		// TODO Consider reusing the same thread (but that would create a delay between "bulk-buffers" because of the
		//  socket calls)
		new Thread(() -> {
			final byte[][] buf = this.buf;
			final int MAX_SIZEOF_IPV6_BYTES = 8 * 4 /* 8  4-hex numbers */ + 7 /* 7 ':' */ + 2 /* \r\n */;

			{
				// TODO This is 10KB, so IF we reuse the same thread, we should consider putting this in a ThreadLocal
				//  (or in a static final if there are no other threads)
				byte[] bulkRequest =
					new byte[HEADER.length + FOOTER.length + REQUEST_BULK_SIZE * MAX_SIZEOF_IPV6_BYTES +
							 4 /* bulkRequest.size() */];

				System.arraycopy(HEADER, 0, bulkRequest, 0, HEADER.length);
				int reqOff = HEADER.length;

				for (int i = start; i < end; ++i) {
					if (BYTE_ARR_HANDLE.compareAndSet(buf, i, null, REQUEST_RESERVED)) continue;
					byte[] singleRequest = (byte[]) BYTE_ARR_HANDLE.getAndSet(buf, i, REQUEST_PROCESSING);
					assert singleRequest != null;
					if (singleRequest == REQUEST_UNWANTED) {
						BYTE_ARR_HANDLE.set(buf, i, null);
						continue;
					}
					System.arraycopy(singleRequest, 0, bulkRequest, reqOff, singleRequest.length);
					reqOff += singleRequest.length;
					bulkRequest[reqOff++] = '\r';
					bulkRequest[reqOff++] = '\n';
				}

				// TODO If we don't reuse auxIoThread, there is no need for it ot be created at this point, since we
				//  return here without ever starting it
				if (reqOff == HEADER.length) return;
				System.arraycopy(FOOTER, 0, bulkRequest, reqOff, FOOTER.length);
				reqOff += FOOTER.length;

				// TODO If we compute bulkRequest.length at compile time, we should change these
				bulkRequest[bulkRequest.length - 1] = (byte) reqOff;
				bulkRequest[bulkRequest.length - 2] = (byte) (reqOff >>> 8);
				bulkRequest[bulkRequest.length - 3] = (byte) (reqOff >>> 16);
				bulkRequest[bulkRequest.length - 4] = (byte) (reqOff >>> 24);

				bulkRequest0.set(bulkRequest);
			}
			auxIoThread.start();
			// TODO If we don't reuse auxIoThread, there is no need for it to use park/unpark synchronization
			// The thread has to be started for `unpark` to guarantee its effects (see method's Javadoc)
			LockSupport.unpark(auxIoThread);

			// TODO can Socket's be reused?
			try (InputStream fromServer = socket.getInputStream(); Socket _socket = socket) {
				// TODO read individually
				// TODO set maximum timeout (we don't want an infinite hang), but make it REALLY big (these
				//  connections can be really slow if they have lots of requests)
				// TODO set maximum size (i.e. ensure the response fits in an array, as arr.length has to be positive)
				byte[] bulkResponses = fromServer.readAllBytes();

				int resOff = Common.skipUntilPastFirst(bulkResponses, 0, bulkResponses.length, '\n', 1, LOGGER);
				if (resOff < 0) return;

				int i = start;
				final int[] offset_prevIpOff_prevIpEnd = { resOff, 0, MAX_SIZEOF_IPV6_BYTES };
				while (i < end) {
					final int singleResOffset = offset_prevIpOff_prevIpEnd[0];
					byte processedCorrectly = readSingleResponse(bulkResponses, offset_prevIpOff_prevIpEnd);
					if (processedCorrectly < 0) return;

					if (processedCorrectly > 0) {
						byte[] singleResponse = Arrays.copyOfRange(bulkResponses, singleResOffset,
																   offset_prevIpOff_prevIpEnd[0]);
						do {
							byte[] requester = (byte[]) BYTE_ARR_HANDLE.compareAndExchange(
								buf, i, REQUEST_PROCESSING, singleResponse);
							if (requester == REQUEST_PROCESSING) {
								LockSupport.unpark(requesters[i]);
								break;
							}
							BYTE_ARR_HANDLE.set(buf, i, null);
							if (requester == REQUEST_RESERVED || requester == null) continue;
							assert requester == REQUEST_UNWANTED;
							break;
						} while (++i < end);
						++i;
					}
				}

				do {
					resOff = offset_prevIpOff_prevIpEnd[0];
					if (resOff == bulkResponses.length ||
						(resOff == bulkResponses.length - 1 && bulkResponses[resOff] == '\n') ||
						(resOff == bulkResponses.length - 2 && bulkResponses[resOff] == '\r' && bulkResponses[resOff + 1] == '\n'))
						break;
					byte processedCorrectly = readSingleResponse(bulkResponses, offset_prevIpOff_prevIpEnd);
					if (processedCorrectly < 0) return;
					if (processedCorrectly > 0) {
						Common.warnUnexpectedPacketReceived(LOGGER, bulkResponses, bulkResponses.length, 0);
						return;
					}
				} while (true);
			} catch (Exception ex) {
				LOGGER.log(Level.SEVERE, "TCP socket exception while receiving data", ex);
			}
		}, "TcpWhoisClient-IoThread-" + start + '-' + end).start();
	}

	private byte readSingleResponse(byte[] bulkResponses, int[] offset_prevIpOff_prevIpEnd) {
		int offset = offset_prevIpOff_prevIpEnd[0];
		final int endOfSingleRes = Common.skipUntilPastFirst(
			bulkResponses, offset, bulkResponses.length, '\n', 2, LOGGER);
		if (endOfSingleRes < 0) return -1;
		offset_prevIpOff_prevIpEnd[0] = endOfSingleRes;


		if (!(
			offset + 4 < bulkResponses.length &&
			bulkResponses[offset] == 'E' &&
			bulkResponses[offset + 1] == 'r' &&
			bulkResponses[offset + 2] == 'r' &&
			bulkResponses[offset + 3] == 'o' &&
			bulkResponses[offset + 4] == 'r'
		)) {
			offset = Common.skipUntilPastFirst(bulkResponses, offset, endOfSingleRes, '|', 3,
											   LOGGER);
			if (offset < 0) return -1;

			while (offset < endOfSingleRes && bulkResponses[offset] == ' ') ++offset;
			if (offset == endOfSingleRes) {
				Common.warnUnexpectedPacketReceived(LOGGER, bulkResponses, bulkResponses.length, 4);
				return -1;
			}

			final int currIpOff = offset;
			while (offset < endOfSingleRes && bulkResponses[offset] != ' ' && bulkResponses[offset] != '|')
				++offset;
			if (offset == endOfSingleRes) {
				Common.warnUnexpectedPacketReceived(LOGGER, bulkResponses, endOfSingleRes, 5);
				return -1;
			}

			// Assume the requests are in ASN order. So if this ip has already
			// been processed, ignore this line
			boolean differentEntries = !Arrays.equals(
				bulkResponses, offset_prevIpOff_prevIpEnd[1], offset_prevIpOff_prevIpEnd[2],
				bulkResponses, currIpOff, offset);
			offset_prevIpOff_prevIpEnd[1] = currIpOff;
			offset_prevIpOff_prevIpEnd[2] = offset;

			return (byte) (differentEntries ? 1 : 0);
		} else {
			return 1;
		}
	}

	private byte @Nullable [] request(byte @NotNull [] ip) {
		final Thread[] requesters = this.requesters;
		final byte[][] buf = this.buf;

		int id;
		Thread t = Thread.currentThread();
		do {
			id = requestId.getAndIncrement() & TOTAL_REQUESTERS_M1;
			if ((id & REQUEST_BULK_SIZE_M1) == 0) {
				int end = id != 0 ? id : TOTAL_REQUESTERS;
				flushRequests(end - REQUEST_BULK_SIZE, end);
			}

			requesters[id] = t;
			// At this point, the id may not refer to this "bulk-buffer" (it
			// may refer to a previous one, but never to a newer one). In that
			// case, the next comparison will fail and the loop will start
			// again (or it may succeed because the thread hasn't read this
			// part of the buffer yet, which is even better).
			if (BYTE_ARR_HANDLE.compareAndSet(buf, id, null, ip)) break;

			assert BYTE_ARR_HANDLE.get(buf, id) == REQUEST_RESERVED;
			// Clean any REQUEST_RESERVED
			BYTE_ARR_HANDLE.set(buf, id, null);
			requesters[id] = null;
		} while (true);

		LockSupport.unpark(periodicFlusher);
		final long until = System.currentTimeMillis() + timeoutMillis;
		byte[] result;
		while ((result = (byte[]) BYTE_ARR_HANDLE.getVolatile(buf, id)) == ip || result == REQUEST_PROCESSING) {
			if (System.currentTimeMillis() > until) {
				requesters[id] = null;
				if (BYTE_ARR_HANDLE.compareAndSet(buf, id, ip, REQUEST_UNWANTED)) return null;
				if (BYTE_ARR_HANDLE.compareAndSet(buf, id, REQUEST_PROCESSING, REQUEST_UNWANTED)) return null;
				continue;
			}
			LockSupport.parkUntil(until);
		}
		assert result != REQUEST_RESERVED;
		assert result != REQUEST_UNWANTED;

		requesters[id] = null;
		BYTE_ARR_HANDLE.setVolatile(buf, id, null);
		return result;
	}

	@Override
	public AS ip2asn(@NotNull InetAddress ip) {
		// TODO Optimize String alloc
		byte[] ip0 = ip.getHostAddress().getBytes(StandardCharsets.US_ASCII);
		byte[] response = request(ip0);
		// TODO Should we retry on timeout?
		if (response == null) return null;

		int offset;
		int asn;
		{
			int[] offset0 = { 0 };
			long asn0 = Common.readIntUntilPipe(response, response.length, offset0, -1, LOGGER);
			if (asn0 < 0) return null;
			asn = (int) asn0;
			offset = offset0[0];
		}


		offset = Common.skipUntilNoMoreSpace(response, offset, response.length, 8, LOGGER);
		if (offset < 0) return null;

		final int startOfIp = offset;
		while (offset < response.length && response[offset] != ' ' && response[offset] != '|') ++offset;
		if (offset == response.length) {
			Common.warnUnexpectedPacketReceived(LOGGER, response, response.length, 9);
			return null;
		}

		if (!Arrays.equals(response, startOfIp, offset, ip0, 0, ip0.length)) {
			LOGGER.severe("The server answered without following the order of the requests!\nExpected IP: " +
						  ip.getHostAddress() + "\nResponse: \"" +
						  new String(response, startOfIp, offset - startOfIp, StandardCharsets.US_ASCII) + '"');
			// TODO Should we retry? We are not logging a warning, we are logging a severe message, as this is
			//  way worse than the server being non-compliant in some aspects: Logging this means we assumed
			//  (wrongly) that the server will always answer in the same order as the requests were made
			return null;
		}

		// We cannot merge the following operations (skip '|' & skip ' ') because the CC may be ""
		offset = Common.skipUntilPastFirst(response, offset, response.length, '|', 10, LOGGER);
		if (offset < 0) return null;
		offset = Common.skipUntilNoMoreSpace(response, offset, response.length, 11, LOGGER);
		if (offset < 0) return null;


		final int startOfCC = offset;
		final int lenOfCC;
		if (response[startOfCC] == '|') {
			// The country code is ""
			lenOfCC = 0;
		} else {
			offset = Common.skipUntilCurrentIs(response, offset, response.length, ' ', 12, LOGGER);
			if (offset < 0) return null;
			lenOfCC = offset - startOfCC;
		}

		while (offset < response.length && (response[offset] == ' ' || response[offset] == '|')) ++offset;
		if (offset == response.length) {
			Common.warnUnexpectedPacketReceived(LOGGER, response, response.length, 13);
			return null;
		}

		final int startOfAsName = offset;
		while (offset < response.length && response[offset] != '\r' && response[offset] != '\n' && response[offset] != '|')
			++offset;
		if (response.length == offset) {
			Common.warnUnexpectedPacketReceived(LOGGER, response, response.length, 14);
			return null;
		} else if (response[offset] == '|') {
			Common.warnUnexpectedPacketReceived(LOGGER, response, response.length, 15);
			return null;
		}

		// TODO Use asName
		String asName = new String(response, startOfAsName, offset - startOfAsName, StandardCharsets.UTF_8);
		String asCC = new String(response, startOfCC, lenOfCC, StandardCharsets.US_ASCII);

		return new AS(asn, asCC);
	}
}
