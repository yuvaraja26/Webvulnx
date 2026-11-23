# WebVulnX Burp Suite Community Extension

This Java extension uses the official Burp Montoya API to send user-selected HTTP requests and responses from Burp Suite Community Edition to the local WebVulnX Flask API (`http://127.0.0.1:5000/api/v1/traffic`).

## Build Instructions (Kali Linux)
```bash
sudo apt update && sudo apt install -y maven default-jdk
mvn clean package
```

The compiled JAR will be created at:
`target/webvulnx-burp-extension-1.0.0.jar`

## Load into Burp Suite Community Edition
1. Open Burp Suite Community Edition.
2. Go to **Extensions** -> **Installed** -> **Add**.
3. Set **Extension type** to **Java**.
4. Select `target/webvulnx-burp-extension-1.0.0.jar`.
5. Click **Next** and verify `[WebVulnX] Extension loaded successfully` appears in the Output tab.
6. In **Proxy** -> **HTTP history**, right-click any Juice Shop (`127.0.0.1:3000`) request and click **Extensions** -> **WebVulnX Connector** -> **Send to WebVulnX**.
