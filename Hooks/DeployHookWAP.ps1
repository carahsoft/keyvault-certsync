param(
    [switch]$quiet
);

function Get-EnvironmentCertificateThumbprint {
    if($env:CERTIFICATE_THUMBPRINT -eq $null) {
        Write-Host "Environment variable CERTIFICATE_THUMBPRINT must be defined" -ForegroundColor Red
        exit 1
    }

    return $env:CERTIFICATE_THUMBPRINT;
}

$thumbprint = Get-EnvironmentCertificateThumbprint

try
{
    if(!$quiet) {
        Write-Host "Assigning $($thumbprint) to WAP"
    }

    Set-WebApplicationProxySslCertificate -Thumbprint $thumbprint
}
catch
{
    Write-Host "Error assigning certificate:" -ForegroundColor Red
    Write-Host "$($_.Exception)" -ForegroundColor Red   
    exit 1
}