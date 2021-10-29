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
        Write-Host "Copying $($thumbprint) to NTDS LocalMachine"
    }

    Copy-Item "HKLM:\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\$($thumbprint)" "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\MY\Certificates\"
}
catch
{
    Write-Host "Error copying certificate:" -ForegroundColor Red
    Write-Host "$($_.Exception)" -ForegroundColor Red   
    exit 1
}