package com.coam.pdfvalidator.infrastructure.revocation;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RevocationUrlGuardTest {

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByAddress(parseIpv4(literal));
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] parseIpv4(String literal) {
        String[] parts = literal.split("\\.");
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }

    private static InetAddress ipv6(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    private static HostResolver fixedResolver(InetAddress... addresses) {
        return host -> addresses;
    }

    @Test
    void aPlainHttpUrlResolvingToAPublicAddressIsAccepted() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ip("93.184.216.34")));
        assertThat(target.uri().getHost()).isEqualTo("ocsp.example.org");
        assertThat(target.address()).isEqualTo(ip("93.184.216.34"));
    }

    @Test
    void anHttpsUrlIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "https://ocsp.example.org/ee", false, fixedResolver(ip("93.184.216.34"))))
                .isInstanceOf(RevocationUrlRejectedException.class)
                .hasMessageContaining("http");
    }

    @Test
    void aMalformedUrlIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://[not a url", false, fixedResolver(ip("93.184.216.34"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void aLoopbackAddressIsRejectedByDefault() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("127.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class)
                .hasMessageContaining("private/loopback/reserved");
    }

    @Test
    void aLinkLocalCloudMetadataAddressIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://metadata.internal/ee", false, fixedResolver(ip("169.254.169.254"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void rfc1918PrivateAddressesAreRejected() {
        for (String literal : new String[] {"10.0.0.1", "172.16.0.1", "192.168.1.1"}) {
            assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                    "http://ocsp.internal/ee", false, fixedResolver(ip(literal))))
                    .as("literal %s", literal)
                    .isInstanceOf(RevocationUrlRejectedException.class);
        }
    }

    @Test
    void cgnatAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("100.64.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
        // 100.128.0.1 is outside the /10 (second octet > 127): must be treated as public.
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ip("100.128.0.1")));
        assertThat(target.address()).isEqualTo(ip("100.128.0.1"));
    }

    @Test
    void zeroSlashEightIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("0.0.0.5"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void multicastAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("224.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void ipv6UniqueLocalAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ipv6("fc00::1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ipv6("fd12:3456::1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    @Test
    void ipv4MappedIpv6PrivateAddressesAreRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ipv6("::ffff:10.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    /** T21e: embeddings of a private/loopback IPv4 address inside other IPv6 forms must not bypass the denylist. */
    @Test
    void ipv6EmbeddingsOfPrivateOrLoopbackIpv4AddressesAreRejected() {
        for (String literal : new String[] {
                "::127.0.0.1",          // IPv4-compatible (deprecated) loopback
                "::10.0.0.1",           // IPv4-compatible RFC 1918
                "::169.254.169.254",    // IPv4-compatible cloud metadata
                "64:ff9b::7f00:1",      // NAT64 well-known prefix, 127.0.0.1
                "64:ff9b::a9fe:a9fe",   // NAT64, 169.254.169.254
                "64:ff9b::a00:1",       // NAT64, 10.0.0.1
                "2002:7f00:1::",        // 6to4, 127.0.0.1
                "2002:a9fe:a9fe::1",    // 6to4, 169.254.169.254
                "2002:c0a8:101::1"      // 6to4, 192.168.1.1
        }) {
            assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                    "http://ocsp.internal/ee", false, fixedResolver(ipv6(literal))))
                    .as("literal %s", literal)
                    .isInstanceOf(RevocationUrlRejectedException.class);
        }
    }

    @Test
    void ipv6EmbeddingsOfPublicIpv4AddressesAreStillAccepted() {
        for (String literal : new String[] {"64:ff9b::5db8:d822", "2002:5db8:d822::1"}) { // 93.184.216.34
            RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                    "http://ocsp.example.org/ee", false, fixedResolver(ipv6(literal)));
            assertThat(target.address()).as("literal %s", literal).isEqualTo(ipv6(literal));
        }
    }

    @Test
    void ipv4MappedIpv6PublicAddressesAreAccepted() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ipv6("::ffff:93.184.216.34")));
        assertThat(target.address()).isEqualTo(ipv6("::ffff:93.184.216.34"));
    }

    @Test
    void privateAddressesAreAllowedWhenExplicitlyEnabledForTesting() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://127.0.0.1:8080/ee", true, fixedResolver(ip("127.0.0.1")));
        assertThat(target.address()).isEqualTo(ip("127.0.0.1"));
    }

    @Test
    void resolvesTheHostnameExactlyOnce() {
        AtomicInteger calls = new AtomicInteger();
        HostResolver resolver = host -> {
            calls.incrementAndGet();
            return new InetAddress[] {ip("93.184.216.34")};
        };
        RevocationUrlGuard.resolve("http://ocsp.example.org/ee", false, resolver);
        assertThat(calls.get()).isEqualTo(1);
    }

    /**
     * The core DNS-rebinding proof at the guard level: given several
     * candidate addresses from one single resolution, the guard must pick
     * the first <em>permitted</em> one from that same call -- it must never
     * call the resolver again (which a hostile authoritative DNS server
     * could answer differently the second time).
     */
    @Test
    void picksTheFirstPermittedAddressFromASingleResolutionWhenAPrivateAddressComesFirst() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false,
                fixedResolver(ip("127.0.0.1"), ip("93.184.216.34")));
        assertThat(target.address()).isEqualTo(ip("93.184.216.34"));
    }

    @Test
    void aHostResolvingOnlyToPrivateAddressesIsRejected() {
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://ocsp.internal/ee", false, fixedResolver(ip("127.0.0.1"), ip("10.0.0.1"))))
                .isInstanceOf(RevocationUrlRejectedException.class);
    }

    // ---- T21c: DNS resolution runs under the deadline ----

    /** A resolver that hangs until released, standing in for a slow or hostile authoritative DNS server. */
    private static final class HangingResolver implements HostResolver {
        final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        final AtomicInteger calls = new AtomicInteger();

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            calls.incrementAndGet();
            // Like a native getaddrinfo call, ignore interruption: only the release frees the thread.
            boolean released = false;
            while (!released) {
                try {
                    release.await();
                    released = true;
                } catch (InterruptedException e) {
                    // keep waiting
                }
            }
            throw new UnknownHostException(host);
        }
    }

    @Test
    void aSlowResolverIsAbandonedWhenTheDnsTimeoutElapses() {
        HangingResolver resolver = new HangingResolver();
        long start = System.nanoTime();
        try {
            assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                    "http://slow.example.org/ee", false, resolver, java.time.Duration.ofMillis(200)))
                    .isInstanceOf(RevocationUrlRejectedException.class)
                    .hasMessageContaining("within the time limit");
        } finally {
            resolver.release.countDown();
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        assertThat(elapsedMillis).isLessThan(1500);
        assertThat(resolver.calls.get()).isEqualTo(1); // resolved once, never retried
    }

    @Test
    void anAlreadyExpiredDnsBudgetRejectsWithoutResolving() {
        HangingResolver resolver = new HangingResolver();
        assertThatThrownBy(() -> RevocationUrlGuard.resolve(
                "http://slow.example.org/ee", false, resolver, java.time.Duration.ZERO))
                .isInstanceOf(RevocationUrlRejectedException.class)
                .hasMessageContaining("within the time limit");
        assertThat(resolver.calls.get()).isZero();
    }

    @Test
    void aFastResolverStillWorksUnderTheDnsTimeout() {
        RevocationUrlGuard.ValidatedTarget target = RevocationUrlGuard.resolve(
                "http://ocsp.example.org/ee", false, fixedResolver(ip("93.184.216.34")),
                java.time.Duration.ofSeconds(1));
        assertThat(target.address()).isEqualTo(ip("93.184.216.34"));
    }

    @Test
    void whenTheResolverPoolIsSaturatedFurtherLookupsAreRejectedInsteadOfQueued() {
        HangingResolver resolver = new HangingResolver();
        try {
            int rejected = 0;
            for (int i = 0; i < RevocationUrlGuard.MAX_CONCURRENT_LOOKUPS + 4; i++) {
                try {
                    RevocationUrlGuard.resolve(
                            "http://slow" + i + ".example.org/ee", false, resolver, java.time.Duration.ofMillis(20));
                } catch (RevocationUrlRejectedException e) {
                    if (e.getMessage().contains("busy")) {
                        rejected++;
                    }
                }
            }
            assertThat(rejected).isGreaterThanOrEqualTo(4);
            assertThat(resolver.calls.get()).isLessThanOrEqualTo(RevocationUrlGuard.MAX_CONCURRENT_LOOKUPS);
        } finally {
            resolver.release.countDown();
        }
    }

    /**
     * T23a: rejection messages are reported to the client by the CRL/OCSP clients, so they must stay fixed texts
     * that never echo the (attacker-supplied) host or URL back.
     */
    @Test
    void rejectionMessagesNeverEchoTheHostOrTheUrl() {
        String[] urls = {"https://evil-host.example/ee", "http://evil-host.example/ee", "ftp://evil-host.example/x"};
        for (String url : urls) {
            assertThatThrownBy(() -> RevocationUrlGuard.resolve(url, false, fixedResolver(ip("127.0.0.1"))))
                    .isInstanceOf(RevocationUrlRejectedException.class)
                    .message().doesNotContain("evil-host").doesNotContain("example");
        }
    }
}
