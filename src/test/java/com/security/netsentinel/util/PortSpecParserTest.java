package com.security.netsentinel.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PortSpecParserTest {

    @Test
    void testParseSinglePort() {
        List<Integer> ports = PortSpecParser.parse("80");
        assertThat(ports).containsExactly(80);
    }

    @Test
    void testParseCommaSeparatedPorts() {
        List<Integer> ports = PortSpecParser.parse("80,443,8080");
        assertThat(ports).containsExactly(80, 443, 8080);
    }

    @Test
    void testParsePortRange() {
        List<Integer> ports = PortSpecParser.parse("20-25");
        assertThat(ports).containsExactly(20, 21, 22, 23, 24, 25);
    }

    @Test
    void testParseMixedListAndRange() {
        List<Integer> ports = PortSpecParser.parse("21, 22, 80-82, 443");
        assertThat(ports).containsExactly(21, 22, 80, 81, 82, 443);
    }

    @Test
    void testParseDuplicatesRemoved() {
        List<Integer> ports = PortSpecParser.parse("80,80,80-82,81");
        assertThat(ports).containsExactly(80, 81, 82);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "abc", "0", "65536", "100-50", "80,invalid", "10-20-30"})
    void testInvalidPortSpecs(String spec) {
        assertThatThrownBy(() -> PortSpecParser.parse(spec))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
