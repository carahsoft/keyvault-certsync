# keyvault-certsync Hooks

## Linux Hooks
The following Linux deploy hooks are included:

* `haproxy-deploy-hook` : Copies certificate to /etc/haproxy/ssl

To download a certificate, copy to HAProxy, and reload the service
```
./keyvault-certsync download -v cscertificates -n mydomain -p /etc/keyvault --deploy-hook "/etc/keyvault-certsync/haproxy-deploy-hook" --post-hook "systemctl reload haproxy.service"
```

Be sure to specify `crt /etc/haproxy/ssl/` in your `/etc/haproxy/haproxy.cfg` frontend bind line.

## Windows Hooks
The following Windows PowerShell deploy hooks are included:

* `DeployHookNTDS.ps1` : Copies certificate from LocalMachine to the Active Directory Domain Services store
* `DeployHookADFS.ps1` : Adds private key permission and assigns certificate to Active Directory Federation Services
* `DeployHookWAP.ps1` : Assigns certificate to the Web Application Proxy
* `DeployHookView.ps1` : Sets certificate friendly name to vdm for VMware Horizon View

To download a certificate and install into the Active Directory service certificate store
```
.\keyvault-certsync download -v cscertificates -n mydomain -s LocalMachine --deploy-hook "PowerShell.exe -ExecutionPolicy Bypass -File C:\ProgramData\keyvault-certsync\DeployHookNTDS.ps1"
```

To download a certificate, mark it exportable, and configure for VMware Horizon View
```
.\keyvault-certsync download -v cscertificates -n mydomain -s LocalMachine --mark-exportable --deploy-hook "PowerShell.exe -ExecutionPolicy Bypass -File C:\ProgramData\keyvault-certsync\DeployHookView.ps1"
```