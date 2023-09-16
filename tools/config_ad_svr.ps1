# install / configure Active Directory Certificate Services
# install the AD CS cmdlets
Install-WindowsFeature Adcs-Cert-Authority
# setup CS parameters
$ad_root_ca_params = @{
CAType = "EnterpriseRootCa"
CryptoProviderName = "ECDSA_P256#Microsoft Software Key Storage Provider"
KeyLength = 256
HashAlgorithmName = "SHA256"
ValidityPeriod = "Years"
ValidityPeriodUnits = 99
}
# install AD CS
Install-AdcsCertificationAuthority @ad_root_ca_params -Confirm:$False