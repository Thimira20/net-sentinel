package com.security.netsentinel.util;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Utility for parsing port specifications (comma-separated lists and ranges).
 */
public class PortSpecParser {

    public static List<Integer> parse(String portSpec) {
        if (portSpec == null || portSpec.isBlank()) {
            throw new IllegalArgumentException("Port specification cannot be empty");
        }

        Set<Integer> ports = new LinkedHashSet<>();
        String[] parts = portSpec.split(",");

        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) {
                continue;
            }

            if (part.contains("-")) {
                String[] range = part.split("-", -1);
                if (range.length != 2) {
                    throw new IllegalArgumentException("Invalid port range format: " + part);
                }
                int start = parsePortNumber(range[0].trim());
                int end = parsePortNumber(range[1].trim());

                if (start > end) {
                    throw new IllegalArgumentException("Invalid port range (start > end): " + part);
                }

                for (int p = start; p <= end; p++) {
                    ports.add(p);
                }
            } else {
                ports.add(parsePortNumber(part));
            }
        }

        if (ports.isEmpty()) {
            throw new IllegalArgumentException("No valid ports found in specification: " + portSpec);
        }

        return new ArrayList<>(ports);
    }

    private static int parsePortNumber(String str) {
        try {
            int port = Integer.parseInt(str);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Port number out of range (1-65535): " + port);
            }
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid port number: " + str, e);
        }
    }
}
