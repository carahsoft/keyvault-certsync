# keyvault-certsync

**keyvault-certsync** is a tool to deploy certificates to Linux and Windows systems from  Azure Key Vault. It supports PKCS12 certificates stored in Azure Key Vault secrets. You can use Azuure App Service to [add and manage TLS/SSL certificates](https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-certificate).

## Install
Build a single file executable for your platform using dotnet publish. Check the [RID Catalog](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog) for other platform identifiers.
```
dotnet publish -r linux-x64 -c Release
dotnet publish -r win-x64-c Release
```

## Authenticatioon
Authentication to Key Vault is performed using [Azure Identity](https://docs.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme) `DefaultAzureCredential`. To automate certificate deployment it is recommended to use environment variables.

For certificate authentication with environment variables
```
export AZURE_CLIENT_ID=
export AZURE_TENANT_ID=
export AZURE_CLIENT_CERTIFICATE_PATH=
```

## Usage
```
  -q, --quiet          Suppress output
  -v, --keyvault       Required. Azure Key Vault name
  -l, --list           Required. List certificates in Key Vault
  -d, --download       Required. Download certificates from Key Vault
  -n, --name           Name of certificate
  -p, --path           Base directory to store certificates
  -s, --store          Windows certificate store (CurrentUser, LocalMachine)
  --mark-exportable    Mark Windows certificate key as exportable
  --help               Display this help screen.
  --version            Display version information.
```

### list

To list all certificates in the Key Vault.
```
./keyvault-certsync -v VAULTNAME -l
```

### download (Linux)

To download all certificates to /etc/keyvault.
```
./keyvault-certsync -v VAULTNAME -d -p /etc/keyvault
```

To download a certificate named website to /etc/keyvault.
```
./keyvault-certsync -v VAULTNAME -d -n website -p /etc/keyvault
```

The files generated follow the same convention as common Let's Encrypt utilities like certbot:

* `privkey.pem` : private key for the certificate
* `fullchain.pem`: the certificate along with CA certificates
* `chain.pem` : CA certificates only
* `cert.pem` : just the certificate

Additionally, following files will be generated:

* `fullchain.privkey.pem` : the concatenation of fullchain and privkey

### download (Windows)

To download all certificates to the LocalMachine certificate store.
```
./keyvault-certsync -v VAULTNAME -d -s LocalMachine
```

To download all certificates to the LocalMachine certificate store and allow the certificate private key to be exported.
```
./keyvault-certsync -v VAULTNAME -d -s LocalMachine --mark-exportable
```

To download all certificates to C:\KeyVault
```
./keyvault-certsync -v VAULTNAME -d -p C:\KeyVault
```