
# ⚙️ AFNSec Event Audit Extension

The **AFNSec Event Audit Extension** adds structured audit logging and SIEM integration to [Apache Guacamole](https://guacamole.apache.org/).  
It logs authentication, session, and administrative events in **JSON**, **CEF**, or **RFC5424** format for enhanced visibility and compliance.

---

## 📥 Download the Extension

Clone the repository

```bash
git clone https://github.com/AFNSec/afnsec-guacamole-extensions.git
```

That will create a local folder:

afnsec-guacamole-extensions/


Move into the specific extension directory
```bash
cd afnsec-guacamole-extensions/guacamole-afnsec-event-audit/
```

Now you’ll see:

```cli
guacamole-afnsec-event-audit-1.0.jar
SHA256SUM.txt
README.md
```

🔐 3. Verify checksum

```bash
sha256sum -c SHA256SUM.txt
```

Expected output:

guacamole-afnsec-event-audit-1.0.jar: OK


If you see “OK,” your file is valid and unmodified.

📦 Install the Extension

Copy the verified JAR into Guacamole’s extension directory:

```bash
sudo install -m 0644 guacamole-afnsec-event-audit-1.0.jar /etc/guacamole/extensions/
```

🔒 Set Permissions

Make sure Tomcat (or the Guacamole web service) can read the file:

```bash
sudo chown root:tomcat /etc/guacamole/extensions/guacamole-afnsec-event-audit-1.0.jar
sudo chmod 0644 /etc/guacamole/extensions/guacamole-afnsec-event-audit-1.0.jar
```

⚙️ Configure guacamole.properties

Open or create /etc/guacamole/guacamole.properties and add the AFNSec audit settings:

```properties
#Minimal startup
# ===== AFNSec Event Audit Configuration =====

# Enable or disable the AFNSec event audit extension.
# Required: true | false
afnsec-audit.enabled: true

# Destination host or IP
# Required
afnsec-audit.syslog-host: 127.0.0.1

# Destination port
# Required
afnsec-audit.syslog-port: 514

# Syslog transport: udp | tcp | tls
# Default: tcp
afnsec-audit.protocol: tcp

# Output format: json | cef | rfc5424
# Default: json
afnsec-audit.format: json

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

[INFO] Loaded extension "AFNSec Event Audit"

and

AFNSec audit initialized: transport=[tcp,udp ortls] host=[ip address], port=[port], format=[format], hostname=[hostname]

📊 Output Example

A typical JSON log event looks like this:

```json
{
  "event_id": "GUAC.AUTH.SUCCESS",
  "event_title": "User authenticated (MFA)",
  "user": {
    "id": "johndoe",
    "auth_provider": "ldap"
  },
  "summary": "johndoe successfully authenticated via LDAP (MFA)",
  "timestamp": "2025-11-02T23:58:01Z",
  "severity": "info",
  "hostname": "guac01"
}
```
📞 Support

For support or security issues:

Email: secops@afnsec.com

© 2025 AFNSec — All rights reserved.
Free for personal and internal organizational use only. Redistribution, resale, or modification are not permitted.
