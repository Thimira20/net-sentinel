package com.security.netsentinel;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.security.netsentinel.engine.PortScannerEngine;
import com.security.netsentinel.model.ScanResult;
import com.security.netsentinel.util.PortSpecParser;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.List;
import java.util.concurrent.Callable;

@Command(
        name = "net-sentinel",
        mixinStandardHelpOptions = true,
        version = "net-sentinel 1.0.0",
        description = "Multi-threaded TCP Port Scanner and Banner Grabber CLI tool."
)
public class NetSentinel implements Callable<Integer> {

    @Option(
            names = {"-t", "--target"},
            required = true,
            description = "Target IP or hostname (required)."
    )
    private String target;

    @Option(
            names = {"-p", "--ports"},
            defaultValue = "21,22,80,443,8080",
            description = "Comma-separated ports or range (e.g., '80,443' or '20-100'). Default: 21,22,80,443,8080"
    )
    private String portsSpec;

    @Option(
            names = {"-c", "--concurrency"},
            defaultValue = "50",
            description = "Maximum concurrent scan tasks. Default: 50"
    )
    private int concurrency;

    @Option(
            names = {"-o", "--output"},
            defaultValue = "text",
            description = "Output format ('text' or 'json'). Default: text"
    )
    private String outputFormat;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public Integer call() {
        if (!"text".equalsIgnoreCase(outputFormat) && !"json".equalsIgnoreCase(outputFormat)) {
            System.err.println("Invalid output format: " + outputFormat + ". Allowed values are 'text' or 'json'.");
            return 1;
        }

        List<Integer> ports;
        try {
            ports = PortSpecParser.parse(portsSpec);
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid port specification: " + e.getMessage());
            return 1;
        }

        PortScannerEngine engine = new PortScannerEngine(target, ports, concurrency);
        List<ScanResult> results = engine.scan();

        if ("json".equalsIgnoreCase(outputFormat)) {
            try {
                String json = OBJECT_MAPPER.writeValueAsString(results);
                System.out.println(json);
            } catch (Exception e) {
                System.err.println("Failed to serialize scan results to JSON: " + e.getMessage());
                return 1;
            }
        } else {
            System.out.println(formatTextResults(target, results));
        }

        return 0;
    }

    public static String formatTextResults(String host, List<ScanResult> results) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scan results for target: ").append(host).append("\n");
        sb.append("----------------------------------------\n");
        for (ScanResult res : results) {
            if (res.isOpen()) {
                sb.append(String.format("Port %-5d/tcp: OPEN   (%d ms)", res.port(), res.latencyMs()));
                if (res.banner() != null && !res.banner().isEmpty()) {
                    sb.append(" | Banner: ").append(res.banner());
                }
                sb.append("\n");
            } else {
                sb.append(String.format("Port %-5d/tcp: CLOSED (%d ms)\n", res.port(), res.latencyMs()));
            }
        }
        return sb.toString().trim();
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new NetSentinel()).execute(args);
        System.exit(exitCode);
    }
}
