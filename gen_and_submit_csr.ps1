# Gather subject name to be used for request
[String]$SubjectNameCN = Read-Host "`nEnter Subject Name CN"

# List and sanitize input for CC/S/A since it is a dropdown in the form and should match what is available
$CCSAOptions = [String[]]("AFIS", "CCEB", "CENTCOM", "CIA", "CONTRACTOR", "DARPA", "DCAA", "DCMA", "DFAS", "DHS", "DIA", "DISA", "DLA",
"DLSA", "DNI", "DOE", "DOJ", "DOS", "DPMO", "DSCA", "DCSA", "DTRA", "DTSA", "DeCA", "DoDEA", "DoDHRA", "DoDIG", "EUCOM", "JFCOM", "JS", 
"MDA", "NASA", "NGA", "NOAA", "NORTHCOM", "NSA/CSS", "OEA", "OSD", "OTHER", "PACOM", "PFPA", "SOCOM", "SOUTHCOM", "STRATCOM", "TMA", 
"TRANSCOM", "TREA", "USA", "USAF", "USCG", "USMC", "USN", "USPHS", "WHS")
Write-Output "`nChoose a CC/S/A item from this list, capitalization counts!"
Write-Output ($CCSAOptions -join ", ")
do {
    [String]$CCSA = Read-Host "`nEnter CC/S/A Value"
} until ($CCSAOptions.Contains($CCSA))

# Enter the host to send the request to
$HostURL = Read-Host "`nEnter URL for Request"

# Create temporary files to use for reading the Key creating info from and generating the csr into
[String]$CSRPath = ".\$($SubjectNameCN)_.csr"
[String]$INFPath = ".\$($SubjectNameCN)_.inf"

$headers = @{
    "Accept"="application/json"
    "Content-Type"="application/json"
}

# I am using the old version of Powershell that ships with Windows.  This is used to skip authentication on the server.
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
 }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# This is the setup file for creating the request
$INF = 
@"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=$SubjectNameCN, OU=$CCSA, OU=PKI, OU=DoD, O=U.S. Government, C=US"
HashAlgorithm = sha256                          ; Request uses sha256 hash
KeyAlgorithm = RSA                              ; Key pair generated using RSA algorithm
Exportable = FALSE                              ; Private key is not exportable
ExportableEncrypted = FALSE                     ; Private key is not exportable encrypted
KeyLength = 2048                                ; KSP key sizes: 2048, 3072, 4096
MachineKeySet = FALSE                           ; True: cert belongs the local computer, False: current user
UseExistingKeySet = FALSE                       ; Do not use an existing key pair
ProviderName = "Microsoft Software Key Storage Provider"
ProviderType = 1
RequestType = PKCS10                            ; Can be CMC, PKCS10, PKCS7 or Cert (self-signed)
"@


# Write INF to file so that the certreq command can read it in
$INF | out-file -filepath $INFPath -force

# Generate request, remove newlines to make the JSON consumable
Write-Output "Generating CSR for $SubjectNameCN"
certreq -new $INFPath $CSRPath
$CertReqData = Get-Content -Raw -Path $CSRPath
$CertReqDataNoNewlines = $CertReqData.Replace("`r`n", "")

# This is the JSONBody used in the POST data.  There are some live substitutions of variables in here, like the CSR and the subjectname
$JSONBody = 
@"
{
    "Attributes": {
        "Attribute": []
    },
    "ProfileID" : "caAltTokenCertCSR",
    "renewal" : false,
    "Input" : [
        {
            "id" : "i1",
            "ClassID" : "keyGenInputImpl",
            "Name" : "Key Generation",
            "Text" : null,
            "Attribute" : [
                {
                    "name" : "cert_request_type",
                    "Value" : "pkcs10",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "Key Generation Request Type",
                        "Syntax" : "keygen_request_type"
                    }
                },
                {
                    "name" : "cert_request",
                    "Value" : "$CertReqDataNoNewlines",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "Key Generation Request",
                        "Syntax" : "keygen_request"
                    }
                }
            ]
        },
        {
            "id" : "i2",
            "ClassID" : "AltTokenSubjectNameInputImpl",
            "ConfigAttribute" : [],
            "Name" : "Subject Name",
            "Text" : null,
            "Attribute" : [
                {
                    "Value" : "$SubjectNameCN",
                    "name" : "subjectname_cn",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "Subject Name CN",
                        "Syntax" : "string"
                    }
                },
                {
                    "Value" : "$CCSA",
                    "name" : "subjectname_ccsa",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "CC/S/A",
                        "Syntax" : "string"
                    }
                },
                {
                    "Value" : null,
                    "name" : "owner_cn",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "CAC CN (required only if different from Subject Name)",
                        "Syntax" : "string"
                    }
                }
            ]
        },
        {
            "id" : "i3",
            "ClassID" : "AltTokenSubjectAltNameInputImpl",
            "ConfigAttribute" : [],
            "Name" : "Subject Alternative Name",
            "Text" : null,
            "Attribute" : [
                {
                    "Value" : null,
                    "name" : "principal_name",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "UPN",
                        "Syntax" : "string"
                    }
                }
            ]
        },
        {
            "id" : "i4",
            "ClassID" : "submitterInfoInputImpl",
            "ConfigAttribute" : [],
            "Name" : "Requestor Information",
            "Text" : null,
            "Attribute" : [
                {
                    "Value" : null,
                    "name" : "requestor_name",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "Requestor Name",
                        "Syntax" : "string"
                    }
                },
                {
                    "Value" : null,
                    "name" : "requestor_email",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "Requestor Email",
                        "Syntax" : "string"
                    }
                },
                {
                    "Value" : null,
                    "name" : "requestor_phone",
                    "Descriptor" : {
                        "Constraint" : null,
                        "DefaultValue" : null,
                        "Description" : "Requestor Phone",
                        "Syntax" : "string"
                    }
                }
            ]
        }
    ]
}
"@

# Submit to the CA with the JSON body above, put the output through the formatter and print the xml returned.
$ReturnedData = Invoke-RestMethod -Uri "https://$HostURL/ca/rest/certrequests" -Method Post -Headers $headers -Body $JSONBody
$RequestNumber
if ($ReturnedData.entries)
{
    Write-Output $ReturnedData.entries
    $RequestNumber = $ReturnedData.entries.requestURL.Split("/")[-1]
}

# Auto Cancel /ca/rest/agent/certrequests/{id}/cancel
$AccessCert = Get-PfxCertificate -FilePath "C:\Users\hrich\Documents\native_windows\sw75.ra.p12"
$CancelURL = "https://10.250.6.49/ca/rest/agent/certrequests/$RequestNumber/approve"
$ReviewURL = "https://10.250.6.49/ca/rest/agent/certrequests/$RequestNumber"
$ReviewData = Invoke-RestMethod -Uri $ReviewURL -Certificate $AccessCert -SessionVariable sesh -Headers $headers
$RequestType = $ReviewData.requestType
$RequestID = $ReviewData.requestID
$Status = $ReviewData.requestStatus
$ProfileName = $ReviewData.profileName
$ProfileID = $ReviewData.profileID
Write-Output "Request Type: $RequestType`nRequest ID: $RequestID`nRequest Status: $Status`nProfile Name: $ProfileName`nProfile ID: $ProfileID"
Write-Output $ReviewData.Input.Attribute
$ConvertedToJSON = $ReviewData | ConvertTo-Json -Depth 12
Write-Output "Approving Reqest ID: $RequestNumber"
$ConfirmApproval = Read-Host "Are you sure you want to approve this request? ([Y]es/[N]o)"
if ($ConfirmApproval -match "y[e]*[s]*$") {
    Invoke-RestMethod -Uri $CancelURL -Method Post -Body $ConvertedToJSON -Certificate $AccessCert -WebSession $sesh

    $ReviewData = Invoke-RestMethod -Uri $ReviewURL -Certificate $AccessCert -Headers $headers
    $RequestID = $ReviewData.requestID
    $Status = $ReviewData.requestStatus
    if ($Status -match "complete") {
        Write-Output "Request Complete!`nRequest ID: $RequestID`nRequest Status: $Status"
    } else {
        Write-Output "Request Not Complete...`nRequest ID: $RequestID`nRequest Status: $Status"
    }
}
# Cleanup of Temp Files
Remove-Item -Path $CSRPath
Remove-Item -Path $INFPath