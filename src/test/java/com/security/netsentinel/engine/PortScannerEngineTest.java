package com.security.netsentinel.engine;

import com.security.netsentinel.model.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

class PortScannerEngineTest {

    private ServerSocket openServer;
    private int openPort;
    private ExecutorService serverExecutor;

    @BeforeEach
    void setUp() throws Exception {
        openServer = new ServerSocket(0); // bind to free port
        openPort = openServer.getLocalPort();
        serverExecutor = Executors.newSingleThreadExecutor();

        // Start mock server thread to accept connection and respond with banner
        serverExecutor.submit(() -> {
            try {
                Socket clientSocket = openServer.accept();
                InputStream in = clientSocket.getInputStream();
                OutputStream out = clientSocket.getOutputStream();

                byte[] buffer = new byte[256];
                int read = in.read(buffer);

                // Send response
                String bannerResponse = "HTTP/1.1 200 OK\r\nServer: MockServer/1.0\r\n\r\n\u0007Hello World!";
                out.write(bannerResponse.getBytes(StandardCharsets.UTF_8));
                out.flush();

                clientSocket.close();
            } catch (Exception ignored) {
            }
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        if (openServer != null && !openServer.isClosed()) {
            openServer.close();
        }
        if (serverExecutor != null) {
            serverExecutor.shutdownNow();
        }
    }

    @Test
    void testCleanBanner() {
        String raw = "HTTP/1.1 200 OK\r\nServer: Test\n\u0000\u0007Special\tChars";
        String cleaned = PortScannerEngine.cleanBanner(raw);
        assertThat(cleaned).isEqualTo("HTTP/1.1 200 OKServer: TestSpecialChars");
    }

    @Test
    void testScanPortOpenAndBannerGrab() {
        ScanResult result = PortScannerEngine.scanPort("127.0.0.1", openPort);
        assertThat(result.isOpen()).isTrue();
        assertThat(result.host()).isEqualTo("127.0.0.1");
        assertThat(result.port()).isEqualTo(openPort);
        assertThat(result.latencyMs()).isGreaterThanOrEqualTo(0);
        assertThat(result.banner()).contains("HTTP/1.1 200 OK");
        assertThat(result.banner()).contains("Server: MockServer/1.0");
        assertThat(result.banner()).doesNotContain("\u0007"); // non-printable cleaned
    }

    @Test
    void testScanPortClosed() {
        // Find an unused port
        int unusedPort;
        try (ServerSocket temp = new ServerSocket(0)) {
            unusedPort = temp.getLocalPort();
        } catch (Exception e) {
            unusedPort = 59999;
        }

        ScanResult result = PortScannerEngine.scanPort("127.0.0.1", unusedPort);
        assertThat(result.isOpen()).isFalse();
        assertThat(result.port()).isEqualTo(unusedPort);
        assertThat(result.banner()).isEmpty();
    }

    @Test
    void testPortScannerEngineMultiplePorts() {
        int unusedPort;
        try (ServerSocket temp = new ServerSocket(0)) {
            unusedPort = temp.getLocalPort();
        } catch (Exception e) {
            unusedPort = 59998;
        }

        final int targetOpenPort = openPort;
        final int targetUnusedPort = unusedPort;

        PortScannerEngine engine = new PortScannerEngine("127.0.0.1", List.of(targetOpenPort, targetUnusedPort), 10);
        List<ScanResult> results = engine.scan();

        assertThat(results).hasSize(2);
        ScanResult openRes = results.stream().filter(r -> r.port() == targetOpenPort).findFirst().orElseThrow();
        ScanResult closedRes = results.stream().filter(r -> r.port() == targetUnusedPort).findFirst().orElseThrow();

        assertThat(openRes.isOpen()).isTrue();
        assertThat(closedRes.isOpen()).isFalse();
    }
}
