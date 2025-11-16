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

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.*;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * DelegatingAuthProvider injects AFNSec warning attributes ONLY when this HttpSession
 * has been flagged by the intel listener (WARN baton promoted to ACTIVE).
 *
 * No policy decisions are made here, this is just the UI bridge for self.
 */

public class DelegatingAuthProvider extends AbstractAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(DelegatingAuthProvider.class);

    /** guacamole.properties: afnsec-intel-passwordcheck-mode = enforce|monitor|warn */
    private static final StringGuacamoleProperty PROP_PASS_MODE = new StringGuacamoleProperty() {
        @Override public String getName() { return "afnsec-intel-passwordcheck-mode"; }
    };

    /** One-shot baton written by the intel listener when mode=warn + hit */
    private static final String BATON  = "AFNSEC_PASS_WARN_FOUND";
    /** Sticky flag for this session to keep WARN visible post-promotion */
    private static final String ACTIVE = "AFNSEC_WARN_ACTIVE";

    private enum PassMode { ENFORCE, MONITOR, WARN }
    private final PassMode passMode;

    public DelegatingAuthProvider() throws GuacamoleException {
        Environment env = LocalEnvironment.getInstance();
        String mode = env.getProperty(PROP_PASS_MODE, "enforce").trim().toLowerCase();
        this.passMode = "warn".equals(mode) ? PassMode.WARN
                : "monitor".equals(mode) ? PassMode.MONITOR
                : PassMode.ENFORCE;
        logger.info("AFNSec DelegatingAuthProvider init. passMode={}", this.passMode);
    }

    @Override
    public String getIdentifier() {
        return "afnsec-threat-intel";
    }

    @Override
    public UserContext decorate(final UserContext context,
                                final AuthenticatedUser authenticatedUser,
                                final Credentials credentials) throws GuacamoleException {

        if (passMode != PassMode.WARN) return context; // Only relevant in WARN mode

        HttpServletRequest req = (credentials != null) ? credentials.getRequest() : null;
        if (req == null) return context;

        HttpSession session;
        try {
            session = req.getSession(false);
        } catch (IllegalStateException e) {
            return context;
        }
        if (session == null) return context;

        boolean baton  = "1".equals(String.valueOf(session.getAttribute(BATON)));
        boolean active = "1".equals(String.valueOf(session.getAttribute(ACTIVE)));

        // Promote oneshot baton to sticky ACTIVE for this session, then clear baton
        if (baton) {
            session.setAttribute(ACTIVE, "1");
            session.removeAttribute(BATON);
            active = true;
        }

        // If not active in THIS session, do not inject any AFNSEC attributes
        if (!active) return context;

        // Decorate /self with AFNSEC banner attributes for this session
        return new DelegatingUserContext(context) {
            @Override
            public User self() {
                final User base = super.self();
                return new org.apache.guacamole.net.auth.DelegatingUser(base) {
                    @Override
                    public Map<String, String> getAttributes() {
                        Map<String, String> attrs = new HashMap<>(
                                super.getAttributes() != null ? super.getAttributes() : Map.of()
                        );
                        attrs.put("afnsec_warn_passhash", "1");
                        attrs.put("afnsec_warn_passhash_text",
                                "Password risk identified. This account’s password matches entries observed in threat-intelligence datasets. To protect access, update your password and avoid reusing passwords across services.");
                        attrs.put("afnsec_warn_passhash_severity", "warning");
                        return attrs;
                    }
                };
            }
        };
    }

    /** Optional utility if you wire a session/cleanup hook later. */
    public static void clearFlags(HttpSession session) {
        if (session != null) {
            session.removeAttribute(BATON);
            session.removeAttribute(ACTIVE);
        }
    }
}
