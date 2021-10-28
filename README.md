# keyvault-certsync

**keyvault-certsync** is a tool to deploy certificates to Linux and Windows systems from  Azure Key Vault. It supports PKCS12 certificates stored in Azure Key Vault secrets. You can use Azuure App Service to [add and manage TLS/SSL certificates](https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-certificate).

## Install
Build a single file executable for your platform using dotnet publish. Check the [RID Catalog](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog) for other platform identifiers.
```
dotnet publish -r linux-x64 -c Release
dotnet publish -r win-x64-c Release
```

## Authentication
Authentication to Key Vault is performed using [Azure Identity](https://docs.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme) `DefaultAzureCredential`. To automate certificate deployment it is recommended to use environment variables.

For certificate authentication with environment variables
```
export AZURE_CLIENT_ID=
export AZURE_TENANT_ID=
export AZURE_CLIENT_CERTIFICATE_PATH=
```

On Windows `ClientCertificateCredential` can be utilized by setting `AZURE_CLIENT_CERTIFICATE_THUMBPRINT` instead of `AZURE_CLIENT_CERTIFICATE_PATH`. The authentication certificate will be checked for in both the CurrentUser and LocalMachine certificate stores.

## Usage
```
  list        List certificates in Key Vault
  download    Download certificates from Key Vault
  upload      Upload certificate to Key Vault
  help        Display more information on a specific command.
  version     Display version information.
```

### list
```
  -v, --keyvault    Required. Azure Key Vault name
  --help            Display this help screen.
  --version         Display version information.
```

To list all certificates in the Key Vault.
```
./keyvault-certsync list -v VAULTNAME
```

### download
```
  -q, --quiet          Suppress output
  -n, --name           Name of certificate. Specify multiple by delimiting with commas.
  -p, --path           (Group: location) Base directory to store certificates
  -s, --store          (Group: location) Windows certificate store (CurrentUser, LocalMachine)
  -f, --force          Force download even when identical local certificate exists
  --mark-exportable    Mark Windows certificate key as exportable
  --post-hook          Run after downloading certificates
  -v, --keyvault       Required. Azure Key Vault name
  --help               Display this help screen.
  --version            Display version information.
```

The files generated follow the same convention as common Let's Encrypt utilities like certbot:

* `privkey.pem` : private key for the certificate
* `fullchain.pem`: the certificate along with CA certificates
* `chain.pem` : CA certificates only
* `cert.pem` : just the certificate

Additionally, following files will be generated:

* `fullchain.privkey.pem` : the concatenation of fullchain and privkey

The post hook will run once and only if certificates are downloaded. The following environment variables will be passed to the script:

* `CERTIFICATE_NAMES` : A comma-separated list of certificate names that were downloaded
* `CERTIFICATE_THUMBPRINTS` : A comma-separated list of certificate thumbprints that were downloaded

#### Linux Examples
To download all certificates to /etc/keyvault.
```
./keyvault-certsync download -v VAULTNAME -p /etc/keyvault
```

To download a certificate named website to /etc/keyvault.
```
./keyvault-certsync download -v VAULTNAME -n website -p /etc/keyvault
```

To run a script after certificates are downloaded. If no certificates are downloaded or all certificates are identical the hook will be ignored.
```
./keyvault-certsync download -v VAULTNAME -p /etc/keyvault --post-hook "systemctl reload haproxy"
```

#### Windows Examples
To download all certificates to the LocalMachine certificate store. 
```
.\keyvault-certsync download -v VAULTNAME -s LocalMachine
```

To download all certificates to the LocalMachine certificate store and allow the certificate private key to be exported.
```
.\keyvault-certsync download -v VAULTNAME -s LocalMachine --mark-exportable
```

To download all certificates to C:\KeyVault
```
.\keyvault-certsync download -v VAULTNAME -p C:\KeyVault
```

### upload
```
  -q, --quiet       Suppress output
  -n, --name        Required. Name of certificate
  -c, --cert        Required. Path to certificate in PEM format
  -k, --key         Required. Path to private key in PEM format
  --chain           Path to CA chain in PEM format
  -f, --force       Force upload even when identical kev vault certificate exists
  -v, --keyvault    Required. Azure Key Vault name
  --help            Display this help screen.
  --version         Display version information.
```

To upload a certificate named website.
```
./keyvault-certsync upload -v VAULTNAME -n website -c cert.pem -k privkey.pem --chain chain.pem
```

## Hooks
The following Windows PowerShell hooks are included:

* `InstallCertificateNTDS.ps1` : Copies certificate from LocalMachine to Active Directory Domain Services store
* `InstallCertificateADFS.ps1` : Adds private key permission and assigns certificate to Active Directory Federation Services
* `InstallCertificateWAP.ps1` : Assigns certificate to Web Application Proxy

To download a certificate and install into the Active Directory service certificate store
```
.\keyvault-certsync download -v cscertificates -n mydomain -s LocalMachine --post-hook "PowerShell.exe -ExecutionPolicy Bypass -File InstallCertificateNTDS.ps1"
```

## Logging
Session output is logged to a monthly rolling log and retained for 6 months. The log directory on Linux is `/var/log/keyvault-certsync/` and Windows `%ProgramData%\keyvault-certsync\`.