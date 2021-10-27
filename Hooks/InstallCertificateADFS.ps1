param(
    [switch]$quiet
);

function Get-EnvironmentCertificateThumbprint {
	if($env:CERTIFICATE_THUMBPRINTS -eq $null) {
		Write-Host "Environment variable CERTIFICATE_THUMBPRINTS must be defined" -ForegroundColor Red
		exit 1
	}

	$thumbprints = $env:CERTIFICATE_THUMBPRINTS.Split(",");

	if($thumbprints.Count -gt 1) {
		Write-Host "Only one certificate thumbprint can be assigned" -ForegroundColor Red
		exit 1
	}

	return $thumbprints[0];
}

function Add-CertificatePrivateKeyPermission {
	param(
		[string]$userName,
		[string]$permission,
		[string]$certStoreLocation,
		[string]$certThumbprint,
		[switch]$quiet
	);

	try
	{
		$rule = new-object security.accesscontrol.filesystemaccessrule $userName, $permission, allow
		$root = "$($env:ProgramData)\microsoft\crypto\rsa\machinekeys"
		$l = ls Cert:$certStoreLocation
		$l = $l |? {$_.thumbprint -like $certThumbprint}
		$l |%{
			$keyname = $_.privatekey.cspkeycontainerinfo.uniquekeycontainername
			$p = [io.path]::combine($root, $keyname)
			if ([io.file]::exists($p))
			{
				$acl = get-acl -path $p
				$acl.addaccessrule($rule)
				if(!$quiet) {
					echo $p
				}
				set-acl $p $acl
			}
		}
	}
	catch
	{
		Write-Host "Error adding private key permission:" -ForegroundColor Red
		Write-Host "$($_.Exception)" -ForegroundColor Red
		exit 1
	}
}

$thumbprint = Get-EnvironmentCertificateThumbprint

if(!$quiet) {
	Write-Host "Adding adfssrv read permission to $($thumbprint)y"
}
Add-CertificatePrivateKeyPermission -userName "nt service\adfssrv" -permission read -certStoreLocation \LocalMachine\My -certThumbprint $thumbprint -quiet:$quiet

try
{
	if((Get-AdfsSyncProperties).Role -eq "PrimaryComputer") {
		if(!$quiet) {
			Write-Host "Assigning $($thumbprint) to ADFS"
		}
		
		Set-AdfsSslCertificate -Thumbprint $thumbprint
		Set-AdfsCertificate -CertificateType 'Service-Communications' -Thumbprint $thumbprint
	}
}
catch
{
	Write-Host "Error assinging certificate:" -ForegroundColor Red
	Write-Host "$($_.Exception)" -ForegroundColor Red	
	exit 1
}