/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.server;

import static io.radiusward.radius.codec.attributes.Ietf.CALLING_STATION_ID;
import static io.radiusward.radius.codec.attributes.Ietf.USER_NAME;

import io.radiusward.common.management.PrometheusWriter;
import io.radiusward.radius.codec.RadiusPacket;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The proxy's home servers (ADR 0037): the configured ones and those discovered in DNS, their pools, which one a
 * request goes to (failover, or load-balanced by device), and which are alive. Used by the proxy's thread; the list
 * and the counters are read by metrics too.
 */
final class HomeServers {

    private static final Logger LOG = LogManager.getLogger(HomeServers.class);

    private final ProxyConfig config;
    private final List<HomeState> all = new CopyOnWriteArrayList<>(); // grows by discovery; read by metrics
    private final Map<InetSocketAddress, HomeState> byAddress = new HashMap<>();
    private final Map<String, int[]> pools = new HashMap<>();
    private final Map<String, Boolean> loadBalanced = new HashMap<>();
    private final javax.net.ssl.SSLContext discoveryContext; // null without discovery

    HomeServers(ProxyConfig config) {
        this.config = config;
        Map<String, Integer> index = new HashMap<>();
        for (ProxyConfig.Home h : config.homes().values()) {
            index.put(h.name(), all.size());
            HomeState s = new HomeState(all.size(), h);
            all.add(s);
            if (s.tls == null) {
                byAddress.put(s.address, s);
            }
        }
        for (ProxyConfig.Pool p : config.pools().values()) {
            pools.put(
                    p.name(),
                    p.servers().stream()
                            .filter(index::containsKey)
                            .mapToInt(index::get)
                            .toArray());
            loadBalanced.put(p.name(), p.loadBalance());
        }
        this.discoveryContext = config.discovery() == ProxyConfig.Discovery.OFF
                ? null
                : TlsClient.context(
                        config.discovery().certificate(),
                        config.discovery().key(),
                        config.discovery().ca());
    }

    /** The home servers of a configured pool, by index; {@code null} for an unknown pool. */
    int[] pool(String name) {
        return pools.get(name);
    }

    HomeState get(int index) {
        return all.get(index);
    }

    /** The UDP home server at {@code sender}, or {@code null}. */
    HomeState at(SocketAddress sender) {
        return byAddress.get(sender);
    }

    List<HomeState> all() {
        return all;
    }

    /** The index of a discovered home server, created once per host and port. */
    int discovered(RealmDiscovery.Target target, java.net.InetAddress address) {
        String name = "discovered:" + target.host() + ":" + target.port();
        for (HomeState h : all) {
            if (h.config.name().equals(name)) {
                return h.index;
            }
        }
        ProxyConfig.Discovery d = config.discovery();
        ProxyConfig.Home h = new ProxyConfig.Home(
                name,
                address,
                target.host(),
                target.port(),
                d.secret(),
                true,
                d.certificate(),
                d.key(),
                d.ca(),
                target.host(),
                false);
        HomeState discovered = new HomeState(all.size(), h, discoveryContext);
        all.add(discovered);
        return discovered.index;
    }

    /** Failover: the first one alive. Load-balance: by device (Calling-Station-Id, else User-Name) among those alive. */
    HomeState choose(String poolName, int[] pool, RadiusPacket request) {
        int alive = 0;
        for (int i : pool) {
            if (all.get(i).alive) {
                alive++;
            }
        }
        if (alive == 0) {
            return all.get(pool[0]); // all dead: try the first; a request is as good a probe as a Status-Server
        }
        int pick = 0;
        if (poolName != null && Boolean.TRUE.equals(loadBalanced.get(poolName)) && alive > 1) {
            int at = request.findAttribute(CALLING_STATION_ID);
            if (at < 0) {
                at = request.findAttribute(USER_NAME);
            }
            int h = 0;
            if (at >= 0) {
                for (int i = 2, n = request.buffer().getByte(at + 1) & 0xFF; i < n; i++) {
                    h = h * 31 + request.buffer().getByte(at + i);
                }
            }
            pick = Math.floorMod(h, alive);
        }
        for (int i : pool) {
            if (all.get(i).alive && pick-- == 0) {
                return all.get(i);
            }
        }
        return all.get(pool[0]);
    }

    /** {@code h} answered: it is alive (again). */
    void alive(HomeState h) {
        h.waitingSince = 0;
        if (!h.alive) {
            h.alive = true;
            LOG.info("home server {} ({}) answers again", h.config.name(), h.address);
        }
    }

    /**
     * Every home server unanswered for {@code proxy.dead.after} while requests waited is dead; each is probed every
     * {@code proxy.status.interval}; connections are kept up.
     */
    void health(long now, Consumer<HomeState> probe) {
        long dead = config.deadAfter().toNanos();
        for (HomeState h : all) {
            if (h.alive && h.waitingSince != 0 && now - h.waitingSince > dead) {
                h.alive = false;
                LOG.warn(
                        "home server {} ({}) is dead: no answer for {}",
                        h.config.name(),
                        h.address,
                        config.deadAfter());
            }
            if (now - h.nextStatus >= 0) {
                h.nextStatus = now + config.statusInterval().toNanos();
                probe.accept(h);
            }
            if (h.tls != null) {
                try {
                    h.tls.tick(now);
                } catch (IOException e) {
                    LOG.debug("home server {}: {}", h.config.name(), e.toString());
                    h.tls.close();
                }
            }
        }
    }

    /** The home server of a RadSec, TCP or DTLS connection. */
    HomeState of(HomeConnection client) {
        for (HomeState h : all) {
            if (h.tls == client) {
                return h;
            }
        }
        throw new IllegalStateException("unknown connection");
    }

    void writeMetrics(PrometheusWriter w, String radiusServer) {
        w.counter("radiusward_server_proxy_requests_total", "Access-Requests proxied to home servers (ADR 0037)");
        for (HomeState h : all) {
            for (Proxy.Counter c : Proxy.Counter.values()) {
                w.sample(
                        h.counts.get(c.ordinal()),
                        "server",
                        radiusServer,
                        "home",
                        h.config.name(),
                        "result",
                        c.name().toLowerCase(Locale.ROOT));
            }
        }
        w.gauge("radiusward_server_proxy_home_alive", "1 while a home server answers");
        for (HomeState h : all) {
            w.sample(h.alive ? 1 : 0, "server", radiusServer, "home", h.config.name());
        }
    }

    void close() {
        for (HomeState h : all) {
            if (h.tls != null) {
                h.tls.close();
            }
        }
    }
}
