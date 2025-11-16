/*
 * Copyright (c) 2025 AFNSec. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this Software for use with Apache Guacamole, to use the Software for
 * personal or internal organizational purposes only, subject to the following
 * conditions:
 *
 *   - The Software may not be sold, sublicensed, redistributed, or hosted as part
 *     of any commercial product or service.
 *   - The Software may not be modified, reverse-engineered, decompiled, or
 *     otherwise altered.
 *   - The above copyright notice and this permission notice shall be included in
 *     all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * This Software is designed for use with Apache Guacamole, which is licensed
 * separately under the Apache License, Version 2.0:
 *   https://www.apache.org/licenses/LICENSE-2.0
 */



package com.afnsec.intel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.language.TranslatableGuacamoleUnauthorizedException;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.event.ApplicationShutdownEvent;
import org.apache.guacamole.net.event.ApplicationStartedEvent;
import org.apache.guacamole.net.event.AuthenticationRequestReceivedEvent;
import org.apache.guacamole.net.event.listener.Listener;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * AFNSec Threat Intel listener
 * Decision order: GEO -> IP Reputation -> Password Reputation
 */
public class IntelAuthenticationListener implements Listener {

    private static final Logger logger = LoggerFactory.getLogger(IntelAuthenticationListener.class);

    // Properties (canonical)
    private static final StringGuacamoleProperty PROP_API_KEY = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-api-key"; }
    };
    private static final BooleanGuacamoleProperty PROP_ALLOW_ON_ERROR = new BooleanGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-allow-on-api-error"; }
    };
    private static final IntegerGuacamoleProperty PROP_CACHE_TTL = new IntegerGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-cache-ttl-seconds"; }
    };
    private static final StringGuacamoleProperty PROP_UI_DETAIL = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-ui-detail"; } // default|category
    };

    // Module kill switches (defaults true)
    private static final BooleanGuacamoleProperty PROP_ENABLE_IP = new BooleanGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-enable-ip"; }
    };
    private static final BooleanGuacamoleProperty PROP_ENABLE_GEO = new BooleanGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-enable-geo"; }
    };
    private static final BooleanGuacamoleProperty PROP_ENABLE_PASS = new BooleanGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-enable-password"; }
    };

    // Private/bogon skipping
    private static final BooleanGuacamoleProperty PROP_SKIP_PRIVATE_IP = new BooleanGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-skip-private-ip"; }
    };
    // RFC1918 + loopback + link-local ipv4
    private static final Pattern PRIVATE_CIDR = Pattern.compile(
            "^(10\\.|127\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[0-1])\\.|169\\.254\\.|0\\.0\\.0\\.0).*"
    );

    // Health agent props (enabled|disabled)
    private static final StringGuacamoleProperty PROP_HEALTH_AGENT = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-health-agent"; }
    };
    private static final IntegerGuacamoleProperty PROP_HEALTH_INTERVAL = new IntegerGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-health-interval-seconds"; }
    };
    private static final IntegerGuacamoleProperty PROP_HEALTH_FAILS = new IntegerGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-health-failure-threshold"; }
    };
    private static final IntegerGuacamoleProperty PROP_HEALTH_RECOV = new IntegerGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-health-recovery-threshold"; }
    };

    // IP reputation - (enforce|monitor)
    private static final StringGuacamoleProperty PROP_IP_REP = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-ipreputation"; }
    };
    private static final StringGuacamoleProperty PROP_IP_MODE = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-ipreputation-mode"; }
    };

    // Geo filters ( enforce|monitor)
    private static final StringGuacamoleProperty PROP_BLOCK_COUNTRY = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-block-countrycode"; }
    };
    private static final StringGuacamoleProperty PROP_BLOCK_CONTINENT = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-block-continent"; }
    };
    private static final StringGuacamoleProperty PROP_GEO_MODE = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-geofilter-mode"; }
    };

    // Password reputation (enforce|monitor|warn)
    private static final StringGuacamoleProperty PROP_PASS_MODE = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-passwordcheck-mode"; }
    };

    // Endpoints
    private static final String BASE_URL = "https://api.afnsec.com";
    private static final String IP_ENDPOINT = "/api/v1/ip/{ip}";
    private static final String PASS_ENDPOINT = "/api/v1/attack-attempts/password-hash/{sha256}";
    private static final String HEALTH_PATH = "/api/v1/healthz";

    // Defaults & constants
    private static final int CONNECT_TIMEOUT_MS = 800;
    private static final int READ_TIMEOUT_MS = 1500;
    private static final int READ_TIMEOUT_MS_DEGRADED = 600;
    private static final int DEFAULT_CACHE_TTL_SECONDS = 30;

    private static final String DEFAULT_HEALTH_AGENT = "enabled";
    private static final int DEFAULT_HEALTH_INTERVAL_SEC = 45;
    private static final int DEFAULT_HEALTH_FAILS = 3;
    private static final int DEFAULT_HEALTH_RECOV = 3;

    private static final long BACKOFF_429_MS = 30_000L;

    // Warn baton key (session attribute)
    private static final String REQ_WARN_FLAG = "AFNSEC_PASS_WARN_FOUND";

    // State
    private static volatile long backoffUntilMs = 0;
    private final ObjectMapper mapper = new ObjectMapper();

    private final String apiKey;
    private final boolean allowOnApiError;
    private final int cacheTtlSeconds;
    private final UiDetail uiDetail;

    // switches & options
    private final boolean enableIp;
    private final boolean enableGeo;
    private final boolean enablePass;
    private final boolean skipPrivateIp;

    private final Mode ipMode;
    private final Set<String> ipBlockVerdicts;
    private final Mode geoMode;
    private final Set<String> blockCountry;
    private final Set<String> blockContinent;
    private final PassMode passMode;

    private final ConcurrentHashMap<String, IpCacheEntry> ipCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, PassCacheEntry> passCache = new ConcurrentHashMap<>();

    private enum UiDetail { DEFAULT, CATEGORY }
    private enum HealthState { UP, DOWN }
    private enum Mode { ENFORCE, MONITOR }
    private enum PassMode { ENFORCE, MONITOR, WARN }
    private enum Policy { REPUTATION, GEO, PASSWORD, HEALTH, API_ERROR }

    // Health agent state
    private volatile HealthState healthState = HealthState.UP;
    private volatile int consecutiveFails = 0;
    private volatile int consecutiveOk = 0;
    private final boolean healthAgentEnabled;
    private final int healthIntervalSec;
    private final int healthFailureThreshold;
    private final int healthRecoveryThreshold;
    private ScheduledExecutorService healthExec;

    // Cache entries
    private static class IpCacheEntry {
        final String verdictNorm, verdictOriginal, continent, country;
        final long expiresAt;
        IpCacheEntry(String vNorm, String vOrig, String cont, String ctry, long exp) {
            verdictNorm = vNorm; verdictOriginal = vOrig; continent = cont; country = ctry; expiresAt = exp;
        }
        boolean expired() { return System.currentTimeMillis() > expiresAt; }
    }
    private static class PassCacheEntry {
        final boolean found; final long expiresAt;
        PassCacheEntry(boolean f, long exp) { found = f; expiresAt = exp; }
        boolean expired() { return System.currentTimeMillis() > expiresAt; }
    }

    public IntelAuthenticationListener() throws GuacamoleException {
        Environment env = LocalEnvironment.getInstance();

        // Required
        this.apiKey = require(env.getProperty(PROP_API_KEY, ""), "afnsec-intel-api-key");

        // Behavior
        this.allowOnApiError = env.getProperty(PROP_ALLOW_ON_ERROR, true);
        this.cacheTtlSeconds = Math.max(0, env.getProperty(PROP_CACHE_TTL, DEFAULT_CACHE_TTL_SECONDS));
        this.uiDetail = env.getProperty(PROP_UI_DETAIL, "default").equalsIgnoreCase("category") ? UiDetail.CATEGORY : UiDetail.DEFAULT;

        // Kill switches (default true)
        this.enableIp   = env.getProperty(PROP_ENABLE_IP,   true);
        this.enableGeo  = env.getProperty(PROP_ENABLE_GEO,  true);
        this.enablePass = env.getProperty(PROP_ENABLE_PASS, true);

        // Skip private/bogon IP lookups (default true)
        this.skipPrivateIp = env.getProperty(PROP_SKIP_PRIVATE_IP, true);

        // IP reputation config
        String repCsv = env.getRequiredProperty(PROP_IP_REP).trim();
        this.ipBlockVerdicts = parseCsvLower(repCsv, "afnsec-intel-ipreputation", "malicious", "suspicious");
        this.ipMode = env.getProperty(PROP_IP_MODE, "enforce").equalsIgnoreCase("monitor") ? Mode.MONITOR : Mode.ENFORCE;

        // Geo config
        this.blockCountry = parseCsvUpper(env.getProperty(PROP_BLOCK_COUNTRY));
        this.blockContinent = parseContinentCsv(env.getProperty(PROP_BLOCK_CONTINENT));
        this.geoMode = env.getProperty(PROP_GEO_MODE, "enforce").equalsIgnoreCase("monitor") ? Mode.MONITOR : Mode.ENFORCE;

        // Password mode
        String pm = env.getProperty(PROP_PASS_MODE, "enforce").trim().toLowerCase();
        this.passMode = pm.equals("warn") ? PassMode.WARN : pm.equals("monitor") ? PassMode.MONITOR : PassMode.ENFORCE;

        // Health agent
        String agent = env.getProperty(PROP_HEALTH_AGENT, DEFAULT_HEALTH_AGENT);
        this.healthAgentEnabled = agent != null && agent.trim().equalsIgnoreCase("enabled");
        this.healthIntervalSec = env.getProperty(PROP_HEALTH_INTERVAL, DEFAULT_HEALTH_INTERVAL_SEC);
        this.healthFailureThreshold = env.getProperty(PROP_HEALTH_FAILS, DEFAULT_HEALTH_FAILS);
        this.healthRecoveryThreshold = env.getProperty(PROP_HEALTH_RECOV, DEFAULT_HEALTH_RECOV);

        logger.info("AFNSec ThreatIntel init. allowOnApiError={}, cacheTtlSec={}, uiDetail={}, " +
                        "enableIp={}, enableGeo={}, enablePass={}, skipPrivateIp={}, " +
                        "ipMode={}, geoMode={}, passMode={}, blockVerdicts={}, blockCountry={}, blockContinent={}, " +
                        "healthAgent={}, intervalSec={}, failThr={}, recovThr={}",
                allowOnApiError, cacheTtlSeconds, uiDetail,
                enableIp, enableGeo, enablePass, skipPrivateIp,
                ipMode, geoMode, passMode, ipBlockVerdicts, blockCountry, blockContinent,
                healthAgentEnabled, healthIntervalSec, healthFailureThreshold, healthRecoveryThreshold);
    }

    private String require(String v, String name) throws GuacamoleException {
        if (v == null || v.trim().isEmpty())
            throw new GuacamoleServerException(name + " is required but missing.");
        return v;
    }

    private static boolean isPrivate(String ip) { return ip != null && PRIVATE_CIDR.matcher(ip).matches(); }

    // Listener entry
    @Override
    @SuppressWarnings("deprecation")
    public void handleEvent(Object event) throws GuacamoleException {
        if (event instanceof ApplicationStartedEvent) { maybeStartHealthAgent(); return; }
        if (event instanceof ApplicationShutdownEvent) { maybeStopHealthAgent(); return; }
        if (!(event instanceof AuthenticationRequestReceivedEvent)) return;

        AuthenticationRequestReceivedEvent authEvent = (AuthenticationRequestReceivedEvent) event;
        Credentials creds = authEvent.getCredentials();
        String ip = (creds != null) ? creds.getRemoteAddress() : null;

        if (ip == null || ip.isEmpty()) {
            logger.warn("afnsec_ipintel decision=ALLOW reason=no_ip");
            return;
        }

        // Private IP short-circuit (still allow password check)
        if (skipPrivateIp && isPrivate(ip)) {
            logger.debug("afnsec_ipintel decision=ALLOW reason=private_ip ip={}", ip);
            if (enablePass) evaluatePassword(creds);
            return;
        }

        // Circuit breaker: health DOWN
        if (healthState == HealthState.DOWN) {
            if (allowOnApiError) {
                logger.warn("afnsec_ipintel decision=ALLOW policy=health reason=down ip={}", ip);
                if (enablePass) evaluatePassword(creds);
                return;
            } else {
                block(ip, "Unknown", Policy.HEALTH, "down", null, null);
                return;
            }
        }

        // 429 backoff window
        long now = System.currentTimeMillis();
        if (now < backoffUntilMs) {
            if (allowOnApiError) {
                logger.warn("afnsec_ipintel decision=ALLOW policy=api_error reason=backoff_active ip={}", ip);
                if (enablePass) evaluatePassword(creds);
                return;
            } else {
                block(ip, "Unknown", Policy.API_ERROR, "backoff_active", null, null);
                return;
            }
        }

        // GEO/IP (only if enabled)
        if (enableIp || enableGeo) {
            IpCacheEntry ipCe = (cacheTtlSeconds > 0) ? ipCache.get(ip) : null;
            LookupResultIP ipLr;
            if (ipCe != null && !ipCe.expired()) {
                ipLr = new LookupResultIP();
                ipLr.apiError = false;
                ipLr.verdictNorm = ipCe.verdictNorm;
                ipLr.verdictOriginal = ipCe.verdictOriginal;
                ipLr.continent = ipCe.continent;
                ipLr.country = ipCe.country;
                decideGeoIp(ip, ipLr, true);
            } else {
                ipLr = queryIpIntel(ip);
                if (ipLr.apiError) {
                    if (ipLr.misconfig401) { block(ip, ipLr.verdictOriginal, Policy.API_ERROR, "invalid_api_key", null, null); return; }
                    if (allowOnApiError) {
                        logger.warn("afnsec_ipintel decision=ALLOW policy=api_error reason={} http_status={} ip={}",
                                (ipLr.httpStatus == 429 ? "rate_limited" : "api_error"), ipLr.httpStatus, ip);
                    } else {
                        block(ip, ipLr.verdictOriginal, Policy.API_ERROR,
                                (ipLr.httpStatus == 429 ? "rate_limited" : "api_error"), null, null);
                        return;
                    }
                } else {
                    if (cacheTtlSeconds > 0) {
                        long exp = System.currentTimeMillis() + cacheTtlSeconds * 1000L;
                        ipCache.put(ip, new IpCacheEntry(ipLr.verdictNorm, ipLr.verdictOriginal, ipLr.continent, ipLr.country, exp));
                    }
                    decideGeoIp(ip, ipLr, false);
                }
            }
        }

        // Password (only if enabled)
        if (enablePass) {
            evaluatePassword(creds);
        }
    }

    private void evaluatePassword(Credentials creds) throws GuacamoleException {
        String password = (creds != null) ? creds.getPassword() : null;
        if (password == null || password.isEmpty()) {
            logger.debug("afnsec_passhash decision=ALLOW reason=absent");
            return;
        }

        String sha256 = sha256Hex(password);
        PassCacheEntry pce = (cacheTtlSeconds > 0) ? passCache.get(sha256) : null;
        LookupResultPass plr;
        if (pce != null && !pce.expired()) {
            plr = new LookupResultPass();
            plr.apiError = false;
            plr.found = pce.found;
            decidePassword(creds, plr, true);
        } else {
            plr = queryPassIntel(sha256);
            if (plr.apiError) {
                if (plr.misconfig401) {
                    block(creds != null ? creds.getRemoteAddress() : "N/A", "Unknown",
                            Policy.API_ERROR, "invalid_api_key", null, null);
                    return;
                }
                if (allowOnApiError) {
                    logger.warn("afnsec_passhash decision=ALLOW reason=api_error http_status={} cache_hit=false", plr.httpStatus);
                    return;
                } else {
                    block(creds != null ? creds.getRemoteAddress() : "N/A", "Unknown",
                            Policy.API_ERROR, (plr.httpStatus == 429 ? "rate_limited" : "api_error"), null, null);
                    return;
                }
            }
            if (cacheTtlSeconds > 0) {
                long exp = System.currentTimeMillis() + cacheTtlSeconds * 1000L;
                passCache.put(sha256, new PassCacheEntry(plr.found, exp));
            }
            decidePassword(creds, plr, false);
        }
    }

    // Decision & blocking
    private void decideGeoIp(String ip, LookupResultIP lr, boolean cacheHit) throws GuacamoleException {
        if (enableGeo && (continentMatch(lr.continent) || countryMatch(lr.country))) {
            if (geoMode == Mode.ENFORCE) {
                logger.warn("afnsec_ipintel decision=BLOCK policy=geo ip={} continent={} country={} verdict={} cache_hit={}",
                        ip, nullToNA(lr.continent), nullToNA(lr.country), lr.verdictOriginal, cacheHit);
                blockWithCategory(Policy.GEO, ip, lr.verdictOriginal, "policy_match", lr.continent, lr.country);
            } else {
                logger.warn("afnsec_ipintel decision=ALLOW policy=geo mode=monitor ip={} continent={} country={} verdict={} cache_hit={}",
                        ip, nullToNA(lr.continent), nullToNA(lr.country), lr.verdictOriginal, cacheHit);
            }
            return;
        }

        if (enableIp && ipBlockVerdicts.contains(lr.verdictNorm)) {
            if (ipMode == Mode.ENFORCE) {
                logger.warn("afnsec_ipintel decision=BLOCK policy=reputation ip={} verdict={} cache_hit={}",
                        ip, lr.verdictOriginal, cacheHit);
                blockWithCategory(Policy.REPUTATION, ip, lr.verdictOriginal, "verdict_match", null, null);
            } else {
                logger.warn("afnsec_ipintel decision=ALLOW policy=reputation mode=monitor ip={} verdict={} cache_hit={}",
                        ip, lr.verdictOriginal, cacheHit);
            }
            return;
        }

        logger.debug("afnsec_ipintel decision=ALLOW policy=none ip={} verdict={} cache_hit={}",
                ip, lr.verdictOriginal, cacheHit);
    }

    private void decidePassword(Credentials creds, LookupResultPass plr, boolean cacheHit) throws GuacamoleException {
        String user = (creds != null && creds.getUsername() != null) ? creds.getUsername() : "N/A";
        if (!plr.found) {
            logger.debug("afnsec_passhash decision=ALLOW reason=not_found cache_hit={} user={}", cacheHit, user);
            return;
        }

        switch (passMode) {
            case ENFORCE:
                logger.warn("afnsec_passhash decision=BLOCK mode=enforce reason=found cache_hit={} user={}", cacheHit, user);
                blockWithCategory(Policy.PASSWORD,
                        creds != null ? creds.getRemoteAddress() : "N/A", "Found", "hash_hit", null, null);
                return;

            case MONITOR:
                logger.warn("afnsec_passhash decision=ALLOW mode=monitor reason=found cache_hit={} user={}", cacheHit, user);
                return;

            case WARN:
                logger.warn("afnsec_passhash decision=ALLOW mode=warn reason=found cache_hit={} user={}", cacheHit, user);
                HttpServletRequest req = (creds != null) ? creds.getRequest() : null; // deprecated but safe in ext
                if (req != null) {
                    req.getSession(true).setAttribute(REQ_WARN_FLAG, "1");
                }
                return;
        }
    }

    private void blockWithCategory(Policy policy, String ip, String verdictOrig, String reason, String continent, String country) throws GuacamoleException {
        String key; String plain;

        if (uiDetail == UiDetail.CATEGORY) {
            switch (policy) {
                case REPUTATION:
                    key = "AFNSEC.ERROR_IP_BLOCKED_REPUTATION";
                    plain = "Sign-in blocked by AFNSec Threat Intelligence (IP Reputation policy).";
                    break;
                case GEO:
                    key = "AFNSEC.ERROR_IP_BLOCKED_GEO";
                    plain = "Sign-in blocked by AFNSec Threat Intelligence (Geo policy).";
                    break;
                case PASSWORD:
                    key = "AFNSEC.ERROR_PASS_BLOCKED_REPUTATION";
                    plain = "Sign-in blocked by AFNSec Threat Intelligence (Password Reputation policy).";
                    break;
                default:
                    key = "AFNSEC.ERROR_BLOCKED";
                    plain = "Sign-in blocked by AFNSec Threat Intelligence.";
            }
        } else {
            key = "AFNSEC.ERROR_BLOCKED";
            plain = "Sign-in blocked by AFNSec Threat Intelligence.";
        }

        logger.warn("afnsec_block decision=BLOCK policy={} reason={} ip={} verdict={} continent={} country={}",
                policy.name().toLowerCase(), reason, ip, nullToNA(verdictOrig), nullToNA(continent), nullToNA(country));

        throw new TranslatableGuacamoleUnauthorizedException(plain, key);
    }

    private void block(String ip, String verdictOrig, Policy policy, String reason, String continent, String country) throws GuacamoleException {
        blockWithCategory(policy, ip, verdictOrig, reason, continent, country);
    }

    // Health agent
    private void maybeStartHealthAgent() {
        if (!healthAgentEnabled) { logger.info("AFNSec health agent: disabled"); return; }
        if (healthExec != null) return;

        healthExec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "afnsec-health-agent");
            t.setDaemon(true);
            return t;
        });

        int firstDelay = 5 + new Random().nextInt(5);
        healthExec.scheduleWithFixedDelay(this::runHealthCheckWithJitter, firstDelay, healthIntervalSec, TimeUnit.SECONDS);
        logger.info("AFNSec health agent: started (interval={}s, failThr={}, recovThr={})",
                healthIntervalSec, healthFailureThreshold, healthRecoveryThreshold);
    }

    private void maybeStopHealthAgent() {
        if (healthExec != null) {
            healthExec.shutdownNow();
            healthExec = null;
            logger.info("AFNSec health agent: stopped");
        }
    }

    private void runHealthCheckWithJitter() {
        try {
            int jitterSec = Math.max(1, (int)Math.round(healthIntervalSec * 0.2 * (new Random().nextDouble() - 0.5) * 2));
            TimeUnit.SECONDS.sleep(Math.max(0, jitterSec));
        } catch (InterruptedException ignored) { return; }
        runHealthCheckOnce();
    }

    private void runHealthCheckOnce() {
        boolean ok = false;
        int http = -1;
        try {
            URI uri = URI.create(BASE_URL + HEALTH_PATH);
            HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "AFNSec-ThreatIntel-GuacExt/1.0");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");
            http = conn.getResponseCode();
            if (http == 200) {
                InputStream in = conn.getInputStream();
                String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                JsonNode root = mapper.readTree(json);
                ok = root != null && root.has("ok") && root.get("ok").asBoolean(false);
            }
            conn.disconnect();
        } catch (Exception ignore) {
            ok = false;
        }

        if (ok) {
            consecutiveOk++;
            consecutiveFails = 0;
            if (healthState == HealthState.DOWN && consecutiveOk >= healthRecoveryThreshold) {
                healthState = HealthState.UP;
                consecutiveOk = 0;
                logger.warn("afnsec_health state=UP transition=recovered http_status={}", http);
            }
        } else {
            consecutiveFails++;
            consecutiveOk = 0;
            if (consecutiveFails >= healthFailureThreshold && healthState != HealthState.DOWN) {
                healthState = HealthState.DOWN;
                consecutiveFails = 0;
                logger.warn("afnsec_health state=DOWN transition=tripped http_status={}", http);
            }
        }
    }

    // Intel lookups
    private LookupResultIP queryIpIntel(String ip) {
        LookupResultIP r = new LookupResultIP();
        try {
            String path = IP_ENDPOINT.replace("{ip}", ip.trim());
            URI uri = URI.create(BASE_URL + path);
            HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "AFNSec-ThreatIntel-GuacExt/1.0");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(healthState == HealthState.DOWN ? READ_TIMEOUT_MS_DEGRADED : READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("X-Api-Key", apiKey);

            r.httpStatus = conn.getResponseCode();
            InputStream in = (r.httpStatus == 200) ? conn.getInputStream() : conn.getErrorStream();

            if (r.httpStatus == 429) beginBackoff();

            if (r.httpStatus != 200) {
                r.apiError = true;
                r.misconfig401 = (r.httpStatus == 401);
                safeClose(in); conn.disconnect(); return r;
            }

            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            conn.disconnect();

            JsonNode root = mapper.readTree(json);
            JsonNode assessment = (root != null) ? root.get("assessment") : null;
            JsonNode verdictNode = (assessment != null) ? assessment.get("verdict") : null;
            String verdict = verdictNode != null ? verdictNode.asText() : "Unknown";
            r.verdictOriginal = verdict;
            r.verdictNorm = verdict.toLowerCase();

            JsonNode info = (root != null) ? root.get("information") : null;
            String countryCode = (info != null && info.has("country_code")) ? info.get("country_code").asText() : null;
            String contCodeRaw = (info != null && info.has("continent_code")) ? info.get("continent_code").asText() : null;
            String contNameRaw = (info != null && info.has("continent_name")) ? info.get("continent_name").asText() : null;

            String contFromName = normalizeContinent(contNameRaw);
            String contFromCode = normalizeContinent(contCodeRaw);
            String continent = (contFromName != null) ? contFromName : contFromCode;
            if (contFromName != null && contFromCode != null && !Objects.equals(contFromName, contFromCode)) {
                logger.warn("afnsec_ipintel geo_mismatch continent name={} code={} normalized_name={} normalized_code={} ip={}",
                        nullToNA(contNameRaw), nullToNA(contCodeRaw), contFromName, contFromCode, ip);
            }

            r.country = countryCode;
            r.continent = continent;

            endBackoffIfNeeded();
            return r;

        } catch (Exception e) {
            r.apiError = true;
            r.errorMessage = e.getClass().getSimpleName();
            return r;
        }
    }

    private LookupResultPass queryPassIntel(String sha256Hex) {
        LookupResultPass r = new LookupResultPass();
        try {
            String path = PASS_ENDPOINT.replace("{sha256}", sha256Hex);
            URI uri = URI.create(BASE_URL + path);
            HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "AFNSec-ThreatIntel-GuacExt/1.0");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(healthState == HealthState.DOWN ? READ_TIMEOUT_MS_DEGRADED : READ_TIMEOUT_MS);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("X-Api-Key", apiKey);

            r.httpStatus = conn.getResponseCode();
            InputStream in = (r.httpStatus == 200) ? conn.getInputStream() : conn.getErrorStream();

            if (r.httpStatus == 429) beginBackoff();

            if (r.httpStatus != 200) {
                r.apiError = true;
                r.misconfig401 = (r.httpStatus == 401);
                safeClose(in); conn.disconnect(); return r;
            }

            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            conn.disconnect();

            JsonNode root = mapper.readTree(json);
            r.found = root != null && root.has("found") && root.get("found").asBoolean(false);

            endBackoffIfNeeded();
            return r;

        } catch (Exception e) {
            r.apiError = true;
            r.errorMessage = e.getClass().getSimpleName();
            return r;
        }
    }

    // Utilities & helpers
    private static void safeClose(InputStream in) {
        try { if (in != null) in.close(); } catch (Exception ignored) {}
    }

    private static String nullToNA(String s) {
        return (s == null || s.isEmpty()) ? "N/A" : s;
    }

    private static Set<String> parseCsvLower(String csv, String propName, String... allowed) throws GuacamoleException {
        Set<String> allow = new HashSet<>(Arrays.asList(allowed));
        Set<String> out = new HashSet<>();
        if (csv == null) throw new GuacamoleServerException(propName + " is required");
        for (String t : csv.split(",")) {
            String s = t.trim().toLowerCase();
            if (s.isEmpty()) continue;
            if (!allow.contains(s))
                throw new GuacamoleServerException("Invalid value in " + propName + ": " + s + " (allowed: " + allow + ")");
            out.add(s);
        }
        return Collections.unmodifiableSet(out);
    }

    private static Set<String> parseCsvUpper(String csv) {
        if (csv == null || csv.trim().isEmpty()) return Collections.emptySet();
        Set<String> out = new HashSet<>();
        for (String t : csv.split(",")) {
            String s = t.trim().toUpperCase();
            if (!s.isEmpty()) out.add(s);
        }
        return Collections.unmodifiableSet(out);
    }

    /** Normalize continent names/codes to AF | AN | AS | OC | EU | NA | SA */
    private static String normalizeContinent(String val) {
        if (val == null) return null;
        String v = val.trim().toLowerCase();
        switch (v) {
            case "af": case "africa": return "AF";
            case "an": case "antarctica": return "AN";
            case "as": case "asia": return "AS";
            case "oc": case "australia": case "oceania": return "OC";
            case "eu": case "europe": return "EU";
            case "na": case "northamerica": case "north-america": return "NA";
            case "sa": case "southamerica": case "south-america": return "SA";
            default: return null;
        }
    }

    /** Parse CSV of continents (names or codes) into normalized 2-letter codes */
    private static Set<String> parseContinentCsv(String csv) {
        if (csv == null || csv.trim().isEmpty()) return Collections.emptySet();
        Set<String> out = new HashSet<>();
        for (String t : csv.split(",")) {
            String code = normalizeContinent(t);
            if (code != null) out.add(code);
            else logger.warn("afnsec_ipintel invalid continent value ignored: {}", t.trim());
        }
        return Collections.unmodifiableSet(out);
    }

    private boolean countryMatch(String ccode) {
        return ccode != null && blockCountry.contains(ccode.toUpperCase().trim());
    }

    private boolean continentMatch(String code) {
        return code != null && blockContinent.contains(code.toUpperCase().trim());
    }

    private void beginBackoff() {
        long now = System.currentTimeMillis();
        if (now >= backoffUntilMs) {
            backoffUntilMs = now + BACKOFF_429_MS;
            logger.warn("afnsec_intel backoff=START reason=429 window_s=30");
        }
    }

    private void endBackoffIfNeeded() {
        long now = System.currentTimeMillis();
        if (now >= backoffUntilMs && backoffUntilMs != 0) {
            logger.warn("afnsec_intel backoff=END");
            backoffUntilMs = 0;
        }
    }

    private static String sha256Hex(String s) throws GuacamoleException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new GuacamoleServerException("Unable to compute SHA-256 hash", e);
        }
    }

    // DTOs
    private static class LookupResultIP {
        boolean apiError = false;
        boolean misconfig401 = false;
        int httpStatus = -1;
        String errorMessage = null;
        String verdictOriginal = "Unknown";
        String verdictNorm = "unknown";
        String country = null;
        String continent = null;
    }

    private static class LookupResultPass {
        boolean apiError = false;
        boolean misconfig401 = false;
        int httpStatus = -1;
        String errorMessage = null;
        boolean found = false;
    }
}
