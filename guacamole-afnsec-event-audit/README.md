
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
