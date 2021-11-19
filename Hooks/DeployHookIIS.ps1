param(
    [switch]$quiet
);

function Get-EnvironmentCertificateName {
    if($env:CERTIFICATE_NAME -eq $null) {
        Write-Host "Environment variable CERTIFICATE_NAME must be defined" -ForegroundColor Red
        exit 1
    }

    return $env:CERTIFICATE_NAME;
}

function Get-EnvironmentCertificateThumbprint {
    if($env:CERTIFICATE_THUMBPRINT -eq $null) {
        Write-Host "Environment variable CERTIFICATE_THUMBPRINT must be defined" -ForegroundColor Red
        exit 1
    }

    return $env:CERTIFICATE_THUMBPRINT;
}

$name = Get-EnvironmentCertificateName
$thumbprint = Get-EnvironmentCertificateThumbprint

try
{
    Import-Module WebAdministration
    foreach($binding in Get-WebBinding) {
        $bindingCert = (Get-ChildItem -Path "Cert:LocalMachine\MY" | Where-Object { $_.Thumbprint -eq $binding.certificateHash })
        
        if($bindingCert.FriendlyName -eq $name) {
            if(!$quiet) {
                Write-Host "Assigning $($thumbprint) to $($binding.bindingInformation)"
            }

            $binding.RebindSslCertificate($thumbprint, "my")
        }
    }
}
catch
{
    Write-Host "Error assigning IIS certificate:" -ForegroundColor Red
    Write-Host "$($_.Exception)" -ForegroundColor Red   
    exit 1
}