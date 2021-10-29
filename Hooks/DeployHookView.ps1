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
    $cert = (Get-ChildItem -Path "Cert:LocalMachine\MY" | Where-Object { $_.FriendlyName -eq "vdm" })

    if($cert -ne $null) {
        if(!$quiet) {
            Write-Host "Removing vdm friendly name on exisiting cert $($cert.Thumbprint)"
        }
        $cert.FriendlyName = ''
    }

    if(!$quiet) {
        Write-Host "Setting $($thumbprint) friendly name"
    }
    
    (Get-ChildItem -Path "Cert:\LocalMachine\My\$($thumbprint)").FriendlyName = 'vdm'
}
catch
{
    Write-Host "Error updating certificate:" -ForegroundColor Red
    Write-Host "$($_.Exception)" -ForegroundColor Red   
    exit 1
}