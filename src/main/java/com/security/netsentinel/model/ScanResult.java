package com.security.netsentinel.model;

/**
 * Record representing the result of scanning a single TCP port on a target host.
 *
 * @param host      the target IP or hostname
 * @param port      the target port number
 * @param isOpen    true if the port is open and responsive, false otherwise
 * @param latencyMs socket connection latency in milliseconds
 * @param banner    banner captured from the open port, or empty string if none
 */
public record ScanResult(
        String host,
        int port,
        boolean isOpen,
        long latencyMs,
        String banner
) {
    public ScanResult {
        if (banner == null) {
            banner = "";
        }
    }
}
