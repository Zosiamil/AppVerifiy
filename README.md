The setx command is used in PowerShell to store API keys as environment variables.
This prevents exposing sensitive data in the repository and allows the application to access them securely.

setx VT_API_KEY "API_KEY"
setx MB_API_KEY "API_KEY"
setx HA_API_KEY "API_KEY"
setx OTX_API_KEY "API_KEY"
