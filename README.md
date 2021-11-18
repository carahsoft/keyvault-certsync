# keyvault-certsync

**keyvault-certsync** is a tool to deploy certificates to Linux and Windows systems from  Azure Key Vault. It supports PKCS12 certificates stored in Azure Key Vault secrets. You can use Azure App Service to [add and manage TLS/SSL certificates](https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-certificate).

Be sure to check out the included [Hooks](Hooks) and [Extras](Extras).

## Install
Build a single file executable for your platform using dotnet publish. Check the [RID Catalog](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog) for other platform identifiers.
```
dotnet publish -r linux-x64 -c Release
dotnet publish -r win-x64 -c Release
```

## Authentication
Authentication to Key Vault is performed using [Azure Identity](https://docs.microsoft.com/en-us/dotnet/api/overview/azure/identity-readme) `DefaultAzureCredential`. To automate certificate deployment it is recommended to use environment variables.

On Windows `ClientCertificateCredential` can be utilized by setting `AZURE_CLIENT_CERTIFICATE_THUMBPRINT` instead of `AZURE_CLIENT_CERTIFICATE_PATH`. The authentication certificate will be checked for in both the CurrentUser and LocalMachine certificate stores.

For certificate authentication with environment variables
```
export AZURE_CLIENT_ID=
export AZURE_TENANT_ID=
export AZURE_CLIENT_CERTIFICATE_PATH=
```

## Configuration
After a successful run any `AZURE_` environment variables will be saved to `config.json` in the configuration directory to be used for future runs. The configuration directory on Linux is `/etc/keyvault-certsync/` and Windows `%ProgramData%\keyvault-certsync\config\`.

## Usage
```
  list        List certificates in Key Vault
  download    Download certificates from Key Vault
  sync        Sync certificates using automation config
  upload      Upload certificate to Key Vault
  delete      Delete certificate from Key Vault
  help        Display more information on a specific command.
  version     Display version information.
```

### list
```
  -v, --keyvault    Required. Azure Key Vault name
  -q, --quiet       Suppress output
  --debug           Enable debug output
  --config          Override directory for config files
  --help            Display this help screen.
  --version         Display version information.
```

To list all certificates in the Key Vault.
```
./keyvault-certsync list -v VAULTNAME
```

### download
```
  -v, --keyvault       Required. Azure Key Vault name
  -n, --name           Name of certificate. Specify multiple by delimiting with commas.
  -p, --path           (Group: location) Base directory to store certificates
  -s, --store          (Group: location) Windows certificate store (CurrentUser, LocalMachine)
  -f, --force          Force download even when identical local certificate exists
  --mark-exportable    Mark Windows certificate key as exportable
  --deploy-hook        Run for each certificate downloaded
  --post-hook          Run after downloading all certificates
  -a, --automate       Generate config to run during sync
  -q, --quiet          Suppress output
  --debug              Enable debug output
  --config             Override directory for config files
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

The `--automate` option will generate a `download_CERTIFICATENAME.json` file in the configuration directory to be used by the `sync` option.

The deploy hook will run for each certificate after it is downloaded.

* `CERTIFICATE_NAME` : Name of the certificate
* `CERTIFICATE_THUMBPRINT` : Thumbprint of the certificate
* `CERTIFICATE_PATH` : Path to certificate folder, if using `--path` option

The post hook will run once after all certificates are downloaded. If no certificates are downloaded or all certificates are identical the hook will be ignored. The following environment variables will be passed to the script:

* `CERTIFICATE_NAMES` : A comma-separated list of certificate names that were downloaded
* `CERTIFICATE_THUMBPRINTS` : A comma-separated list of certificate thumbprints that were downloaded

#### Linux Examples
To download all certificates to /etc/keyvault.
```
./keyvault-certsync download -v VAULTNAME -p /etc/keyvault
```

To download a certificate named website to /etc/keyvault and generate config to run during sync.
```
./keyvault-certsync download -v VAULTNAME -n website -p /etc/keyvault -a
```

To run a script after all certificates are downloaded.
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

### sync
```
  -f, --force    Force even when identical certificate exists
  -q, --quiet    Suppress output
  --debug        Enable debug output
  --config       Override directory for config files
  --help         Display this help screen.
  --version      Display version information.
``` 

This will download all certificates that have configs generated by the download `--automate` option. Any post hooks will be de-duplicated and run after all certificates have been downloaded.

To run sync quietly, which is useful for cron jobs.
```
.\keyvault-certsync sync -q
```

### upload
```
  -v, --keyvault    Required. Azure Key Vault name
  -n, --name        Required. Name of certificate
  -c, --cert        Required. Path to certificate in PEM format
  -k, --key         Required. Path to private key in PEM format
  --chain           Path to CA chain in PEM format
  -f, --force       Force upload even when identical kev vault certificate exists
  -q, --quiet       Suppress output
  --debug           Enable debug output
  --config          Override directory for config files
  --help            Display this help screen.
  --version         Display version information.
```

To upload a certificate named website.
```
./keyvault-certsync upload -v VAULTNAME -n website -c cert.pem -k privkey.pem --chain chain.pem
```

### delete
```
  -v, --keyvault    Required. Azure Key Vault name
  -n, --name        Required. Name of certificate
  -q, --quiet       Suppress output
  --debug           Enable debug output
  --config          Override directory for config files
  --help            Display this help screen.
  --version         Display version information.
```

To delete a certificate named website.
```
./keyvault-certsync delete -v VAULTNAME -n website
```

## Logging
Session output is logged to a monthly rolling log and retained for 6 months. The log directory on Linux is `/var/log/keyvault-certsync/` and Windows `%ProgramData%\keyvault-certsync\logs\`.
