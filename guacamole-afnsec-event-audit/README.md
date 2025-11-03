
# ⚙️ AFNSec Event Audit Extension

The **AFNSec Event Audit Extension** adds structured audit logging and SIEM integration to [Apache Guacamole](https://guacamole.apache.org/).  
It logs authentication, session, and administrative events in **JSON**, **CEF**, or **RFC5424** format for enhanced visibility and compliance.

---

## 📥 Download the Extension

Use `curl` to download the latest binary and its checksum directly from GitHub:

```bash
# Replace version numbers as needed
curl -LO https://github.com/afnsec/afnsec-guacamole-extensions/raw/main/guacamole-afnsec-event-audit/guacamole-afnsec-event-audit-1.0.0-guac1.6.jar
curl -LO https://github.com/afnsec/afnsec-guacamole-extensions/raw/main/guacamole-afnsec-event-audit/SHA256SUM.txt
```

🔐 Verify File Integrity

Ensure that the JAR you downloaded matches the official checksum:

```bash
sha256sum -c SHA256SUM.txt
```

Expected output:

guacamole-afnsec-event-audit-1.0.0-guac1.6.jar: OK


If you see “OK,” your file is valid and unmodified.

📦 Install the Extension

Copy the verified JAR into Guacamole’s extension directory:

```bash
sudo install -m 0644 guacamole-afnsec-event-audit-1.0.0-guac1.6.jar /etc/guacamole/extensions/
```

🔒 Set Permissions

Make sure Tomcat (or the Guacamole web service) can read the file:

```bash
sudo chown root:tomcat /etc/guacamole/extensions/guacamole-afnsec-event-audit-1.0.0-guac1.6.jar
sudo chmod 0644 /etc/guacamole/extensions/guacamole-afnsec-event-audit-1.0.0-guac1.6.jar
```

⚙️ Configure guacamole.properties

Open or create /etc/guacamole/guacamole.properties and add the AFNSec audit settings:

```properties
# ===== AFNSec Event Audit Configuration =====

# Enable or disable the audit extension
afnsec-audit.enabled: true

# Syslog or SIEM destination
afnsec-audit.syslog-host: 127.0.0.1
afnsec-audit.syslog-port: 514
afnsec-audit.protocol: tcp

# Logging format: json, cef, or rfc5424
afnsec-audit.format: json

# Optional TLS parameters (for remote syslog)
afnsec-audit.tls-enabled: true
afnsec-audit.tls-verify: true
afnsec-audit.tls-truststore: /etc/ssl/certs/ca-certificates.crt

# Log verbosity: info, debug, warn, error
afnsec-audit.log-level: info
```

Save the file.

🔁 Restart Guacamole Services

Apply the configuration by restarting Tomcat and Guacd:

```bash
sudo systemctl restart tomcat9
sudo systemctl restart guacd
```

✅ Verify the Extension Loaded

Check the Tomcat logs to confirm successful load:

```bash
sudo journalctl -u tomcat9 -b | grep afnsec
```

You should see:

```bash
[INFO] Loaded extension "AFNSec Event Audit"
```

and

```bash
AFNSec audit initialized: transport=[tcp,udp ortls] host=[ip address], port=[port], format=[format], hostname=[hostname]
```


📊 Output Example

A typical JSON log event looks like this:

```json
{
  "event_id": "GUAC.AUTH.SUCCESS",
  "event_title": "User authenticated (MFA)",
  "user": {
    "id": "lesleytambe",
    "auth_provider": "ldap"
  },
  "summary": "lesleytambe successfully authenticated via LDAP (MFA)",
  "timestamp": "2025-11-02T23:58:01Z",
  "severity": "info",
  "hostname": "secureconnect01"
}
```
📞 Support

For support or security issues:

Email: secops@afnsec.com

© 2025 AFNSec — All rights reserved.
Free for personal and internal organizational use only. Redistribution, resale, or modification are not permitted.
