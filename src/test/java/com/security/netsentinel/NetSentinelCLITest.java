package com.security.netsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import picocli.CommandLine;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

class NetSentinelCLITest {

    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;
    private ByteArrayOutputStream outContent;
    private ByteArrayOutputStream errContent;

    private ServerSocket openServer;
    private int openPort;
    private ExecutorService serverExecutor;

    @BeforeEach
    void setUp() throws Exception {
        outContent = new ByteArrayOutputStream();
        errContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));

        openServer = new ServerSocket(0);
        openPort = openServer.getLocalPort();
        serverExecutor = Executors.newSingleThreadExecutor();

        serverExecutor.submit(() -> {
            try {
                Socket clientSocket = openServer.accept();
                OutputStream out = clientSocket.getOutputStream();
                out.write("SSH-2.0-OpenSSH_8.9p1\r\n".getBytes(StandardCharsets.UTF_8));
                out.flush();
                clientSocket.close();
            } catch (Exception ignored) {
            }
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        System.setOut(originalOut);
        System.setErr(originalErr);

        if (openServer != null && !openServer.isClosed()) {
            openServer.close();
        }
        if (serverExecutor != null) {
            serverExecutor.shutdownNow();
        }
    }

    @Test
    void testCLITextOutput() {
        CommandLine cmd = new CommandLine(new NetSentinel());
        int exitCode = cmd.execute("-t", "127.0.0.1", "-p", String.valueOf(openPort), "-o", "text");

        assertThat(exitCode).isEqualTo(0);
        String output = outContent.toString();
        assertThat(output).contains("Scan results for target: 127.0.0.1");
        assertThat(output).contains("Port " + openPort);
        assertThat(output).contains("/tcp: OPEN");
        assertThat(output).contains("SSH-2.0-OpenSSH_8.9p1");
    }

    @Test
    void testCLIJsonOutput() throws Exception {
        CommandLine cmd = new CommandLine(new NetSentinel());
        int exitCode = cmd.execute("-t", "127.0.0.1", "-p", String.valueOf(openPort), "-o", "json");

        assertThat(exitCode).isEqualTo(0);
        String output = outContent.toString();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(output);

        assertThat(jsonNode.isArray()).isTrue();
        assertThat(jsonNode.size()).isEqualTo(1);
        JsonNode result = jsonNode.get(0);
        assertThat(result.get("host").asText()).isEqualTo("127.0.0.1");
        assertThat(result.get("port").asInt()).isEqualTo(openPort);
        assertThat(result.get("isOpen").asBoolean()).isTrue();
        assertThat(result.get("banner").asText()).isEqualTo("SSH-2.0-OpenSSH_8.9p1");
    }

    @Test
    void testCLIInvalidOutputFormat() {
        CommandLine cmd = new CommandLine(new NetSentinel());
        int exitCode = cmd.execute("-t", "127.0.0.1", "-o", "xml");

        assertThat(exitCode).isEqualTo(1);
        assertThat(errContent.toString()).contains("Invalid output format: xml");
    }

    @Test
    void testCLIMissingTarget() {
        CommandLine cmd = new CommandLine(new NetSentinel());
        int exitCode = cmd.execute("-p", "80");

        assertThat(exitCode).isNotEqualTo(0);
    }
}
