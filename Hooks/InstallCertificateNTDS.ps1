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

$thumbprint = Get-EnvironmentCertificateThumbprint

try
{
	if(!$quiet) {
		Write-Host "Copying $($thumbprint) to NTDS LocalMachine"
	}

	Copy-Item "HKLM:\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\$($thumbprint)" "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\MY\Certificates\"
}
catch
{
	Write-Host "Error assinging certificate:" -ForegroundColor Red
	Write-Host "$($_.Exception)" -ForegroundColor Red	
	exit 1
}