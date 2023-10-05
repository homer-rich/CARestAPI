# Gather subject name to be used for request
[String]$SubjectNameCN = Read-Host "`nEnter Subject Name CN for the new certificate"

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
$EEHost = Read-Host "`nEnter URL for the Request i.e. ee-sw-ca-75.c3pki.nit.disa.mil"
$AgentHost = $EEHost.Replace("ee", "agent")

$ProfileToRun = "caAltTokenCertCSR"

#$AccessCert = Get-PfxCertificate -FilePath ".\RA.Rich.Homer.p12"

# Create temporary files to use for reading the Key creating info from and generating the csr into
[String]$CSRPath = ".\$($SubjectNameCN)_.csr"
[String]$INFPath = ".\$($SubjectNameCN)_.inf"
[String]$CertDataPath = ".\$($SubjectNameCN)_$($CCSA).cer"

# Headers to pass into each call, that way JSON is sent back.
$headers = @{
    "Accept"="application/json"
    "Content-Type"="application/json"
}

$PotentialCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and $_.Issuer -match "DOD*"}
$PotentialCerts | Format-Table -Property Thumbprint, Subject
$RAThumbprint = Read-Host "Copy and paste your RA thumbprint here from the above table"
$RACertificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey -and $_.Thumbprint -eq $RAThumbprint }

$TestAuthURI = "https://$AgentHost/ca/rest/agent/certrequests"
Write-Output "`nAttempting connection to $TestAuthURI`nwith RA: $($RACertificate.Subject)"
try {
    Invoke-RestMethod -Uri $TestAuthURI -Certificate $RACertificate -Headers $headers | Out-Null
} catch {
    "`nError Occurred while attempting to use your RA token...Exiting"
    Exit
}
Write-Output "`nConnection Successful!"

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

# Retrieve the JSON value of the profile, and edit the values needed for submitting it to the portal.
$RetrieveProfileJSON = "https://$EEHost/ca/rest/certrequests/profiles/$ProfileToRun"
$BaseJSONProfile = Invoke-RestMethod -Uri $RetrieveProfileJSON -Headers $headers
# These are edits to the profile before submitting
($BaseJSONProfile.Input[0].Attribute | Where-Object{$_.name -eq "cert_request_type"}).Value = "pkcs10"
($BaseJSONProfile.Input[0].Attribute | Where-Object{$_.name -eq "cert_request"}).Value = "$CertReqDataNoNewlines"
($BaseJSONProfile.Input[1].Attribute | Where-Object{$_.name -eq "subjectname_cn"}).Value = "$SubjectNameCN"
($BaseJSONProfile.Input[1].Attribute | Where-Object{$_.name -eq "subjectname_ccsa"}).Value = "$CCSA"
# Conversion to a String that is friendly enough to submit to the CA as a Body, default conversion is depth 2
$JSONString =  $BaseJSONProfile | ConvertTo-Json -Depth 12 

# Submit to the CA with the JSON body above, put the output through the formatter and print the xml returned.
$ReturnedData = Invoke-RestMethod -Uri "https://$EEHost/ca/rest/certrequests" -Method Post -Headers $headers -Body $JSONString
$RequestNumber
if ($ReturnedData.entries)
{
    Write-Output "Request Submitted! Now Pending Approval"
    Write-Output $ReturnedData.entries.CertReqInput
    $RequestNumber = $ReturnedData.entries.requestURL.Split("/")[-1]
}

$ApproveURL = "https://$AgentHost/ca/rest/agent/certrequests/$RequestNumber/approve"
$ReviewURL = "https://$AgentHost/ca/rest/agent/certrequests/$RequestNumber"
$RetrieveURL = "https://$EEHost/ca/rest/certrequests/$RequestNumber"

# This call saves the session(cookies and identifiers) in a local variable called sesh
$ReviewData = Invoke-RestMethod -Uri $ReviewURL -Certificate $RACertificate -SessionVariable sesh -Headers $headers
$RequestType = $ReviewData.requestType
$RequestID = $ReviewData.requestID
$Status = $ReviewData.requestStatus
$ProfileID = $ReviewData.profileID
Write-Output "Request Type: $RequestType`nRequest ID: $RequestID`nRequest Status: $Status`nProfile ID: $ProfileID"
$ConvertedToJSON = $ReviewData | ConvertTo-Json -Depth 12
$ConfirmApproval = Read-Host "Do you approve this request? ([Y]es/[N]o)"
if ($ConfirmApproval -match "y[e]*[s]*$") {
    # Reuses the session varaible from the ReviewData call above
    Invoke-RestMethod -Uri $ApproveURL -Method Post -Body $ConvertedToJSON -Certificate $RACertificate -WebSession $sesh
    # Call Review again to see the final status
    $ReviewData = Invoke-RestMethod -Uri $ReviewURL -Certificate $RACertificate -Headers $headers
    $Status = $ReviewData.requestStatus
    if ($Status -match "complete") {
        Write-Output "Request Status: $Status"
       
        # This retrieves the URL for the certificate from the approved request data
        $ReturnedData = Invoke-RestMethod -Uri $RetrieveURL -Headers $headers -Certificate $RACertificate
        if ($ReturnedData) {
            # Now we call the certificate retrieval URL and grab the cert data, write it to a file, and accept it into CAPI
            $CertURL = $ReturnedData.certURL
            $ReturnedData = Invoke-RestMethod -Uri $CertURL -Headers $headers -Certificate $RACertificate
            $CertData = $ReturnedData.Encoded
            $CertData | out-file -filepath $CertDataPath -force
            $ConfirmApproval = Read-Host "Would you like to install this certificate on this computer? ([Y]es/[N]o)"
            if ($ConfirmApproval -match "y[e]*[s]*$") {
                certreq -accept $CertDataPath
            }
        }
        
    } else {
        Write-Output "Request Not Complete...`nRequest ID: $RequestID`nRequest Status: $Status"
    }
}


# Cleanup of Temp Files
Write-Output "Cleaning up temporary files..."
Remove-Item -Path $CSRPath
Remove-Item -Path $INFPath
Read-Host "Done.  Script is finished, press enter to exit"