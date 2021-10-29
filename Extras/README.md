# keyvault-certsync Extras

## Certbot

`certbot/keyvault-deply-hook` is a Certbot deploy hook that calls `keyvault-certsync` to upload a certificate. This hook can be placed in `/etc/letsencrypt/renew-hooks/deploy` or passed as an argument to `certbot` with `--deploy-hook`.

The hook translates the domain name to a certificate name by doing the following:
1. If it exists, `.com` is removed from the end
2. Any `.` are removed

For example `www.domain.com` translates to `wwwdomain` and `domain.net` translates to `domainnet`.

Lastly, make sure to edit `keyvault-deply-hook` and replace `YOUR_VAULT_NAME` with the key vault name.