package com.security.netsentinel.engine;

import com.security.netsentinel.model.ScanResult;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;

/**
 * Network scanning engine using Java 21 Virtual Threads.
 */
public class PortScannerEngine {

    private static final int CONNECT_TIMEOUT_MS = 1200;
    private static final int READ_TIMEOUT_MS = 1000;
    private static final int MAX_BANNER_BYTES = 256;

    private final String target;
    private final List<Integer> ports;
    private final int concurrency;

    public PortScannerEngine(String target, List<Integer> ports, int concurrency) {
        if (target == null || target.isBlank()) {
            throw new IllegalArgumentException("Target cannot be empty");
        }
        if (ports == null || ports.isEmpty()) {
            throw new IllegalArgumentException("Ports list cannot be empty");
        }
        if (concurrency < 1) {
            throw new IllegalArgumentException("Concurrency must be at least 1");
        }
        this.target = target;
        this.ports = ports;
        this.concurrency = concurrency;
    }

    public List<ScanResult> scan() {
        Semaphore semaphore = new Semaphore(concurrency);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Callable<ScanResult>> tasks = new ArrayList<>();

            for (int port : ports) {
                tasks.add(() -> {
                    semaphore.acquire();
                    try {
                        return scanPort(target, port);
                    } finally {
                        semaphore.release();
                    }
                });
            }

            List<Future<ScanResult>> futures = executor.invokeAll(tasks);
            List<ScanResult> results = new ArrayList<>();
            for (Future<ScanResult> future : futures) {
                results.add(future.get());
            }
            return results;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Scan interrupted", e);
        } catch (Exception e) {
            throw new RuntimeException("Scan failed", e);
        }
    }

    public static ScanResult scanPort(String host, int port) {
        long startTime = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            long latencyMs = System.currentTimeMillis() - startTime;

            socket.setSoTimeout(READ_TIMEOUT_MS);
            String banner = grabBanner(socket);

            return new ScanResult(host, port, true, latencyMs, banner);
        } catch (Exception e) {
            long latencyMs = System.currentTimeMillis() - startTime;
            return new ScanResult(host, port, false, latencyMs, "");
        }
    }

    private static String grabBanner(Socket socket) {
        try {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Send minimal probe
            byte[] probe = "HEAD / HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.UTF_8);
            out.write(probe);
            out.flush();

            byte[] buffer = new byte[MAX_BANNER_BYTES];
            int bytesRead = in.read(buffer, 0, MAX_BANNER_BYTES);

            if (bytesRead <= 0) {
                return "";
            }

            String rawBanner = new String(buffer, 0, bytesRead, StandardCharsets.UTF_8);
            return cleanBanner(rawBanner);
        } catch (Exception e) {
            return "";
        }
    }

    public static String cleanBanner(String raw) {
        if (raw == null) {
            return "";
        }
        // Retain printable ASCII characters (hex 20-7E)
        return raw.replaceAll("[^\\x20-\\x7E]", "").trim();
    }
}
