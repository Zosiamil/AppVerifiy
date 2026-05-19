# AppVerifiy

A multi-threaded desktop application (GUI) designed to support SOC analysts during the initial file triage and malware analysis process.

## 🚀 Key Features

* **Threat Intelligence Integration:** Automated lookups via API to query external databases (**VirusTotal, MalwareBazaar by Abuse.ch, Hybrid Analysis, and AlienVault OTX**) for file reputation and threat indicators.
* **Static File Analysis:** Computes file hashes (SHA-256) and calculates **file entropy** to detect potential obfuscation, encryption, or packing techniques.
* **Windows Event Logs Automation:** Leverages PowerShell scripting to automatically scan local system logs (`Security`, `Microsoft-Windows-Windows Defender/Operational`, and `Application`) for any traces of execution or related application crashes.
* **Asynchronous Execution:** Built with multi-threading support (`threading`) to ensure the Tkinter user interface remains smooth and responsive while performing remote API requests.

## 🛠️ Configuration & Setup

Before running the application, you need to set up your API keys for the respective threat intelligence services as environment variables. You can obtain free API keys by creating a free account on each of the platforms listed above.

You can configure them in Windows using PowerShell:
setx VT_API_KEY "API_KEY"
setx MB_API_KEY "API_KEY"
setx HA_API_KEY "API_KEY"
setx OTX_API_KEY "API_KEY"

The setx command is used in PowerShell to store API keys as environment variables.
This prevents exposing sensitive data in the repository and allows the application to access them securely.

