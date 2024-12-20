﻿## Use X509 to redeem Authz Code

### Purpose

Provide support for using X509 cert (asymmetric keys) to redeem the authorization code in OAuth2 flow, when using Microsoft Identity Web toolkit. Currently, the toolkit supports only use of symmetric secrets (ClientSecret) in 
that flow (https://github.com/AzureAD/microsoft-identity-web/issues/3154). (MSAL does support X509 for the client credentials flow.)

Also shows use of *claims* parameter in token request to step-up authentication (see *Privacy* action of the *Home* controller).

### Create cert

```Powershell
$certname = "ups-app4"
$cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1)
Export-Certificate -Cert $cert -FilePath "C:\temp\$certname.cer"  
```

### Register app

Upload .cer (public key of the cert) to app secrets in Entra ID app registration.

### Modify app

Check program.cs for changes.

## Step-up 2nd FA (unrelated to above)

Under Conditional Access Policies:

1. Register an Authentication Context, e.g. Require 2nd FA with claim value id (e.g. c1)
2. Create a Conditional Access policy:

a. under Target Resources select the above context
b. define Require Authentication Strength control: MFA

Have app add

```
%7B%22id_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22c1%22%7D%7D%7D
```
which is url-encoded:
```
{"id_token":{"acrs":{"essential":true,"value":"c1"}}}

https://login.microsoftonline.com/MngEnv350432.onmicrosoft.com/oauth2/v2.0/authorize?client_id=97f0c70c-5fa2-4d1c-b594-cda35a52a697&nonce=nonce&response_mode=fragment&response_type=id_token&scope=openid+profile+email&sso_nonce=AwABEgEAAAADAOz_BQD0_7lVa8gXY3RnTntupZdpYG-9_jQPs6Leew_kFv9UAopU5WnahQM3ArjB2_xrdBAy4TNSLEe5WvSPKOsys0PsM00gAA&client-request-id=09f6fffc-af73-4a5a-8b58-c48252e0ce3c&mscrid=09f6fffc-af73-4a5a-8b58-c48252e0ce3c&claims=%7B%22id_token%22%3A%7B%22acrs%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22c1%22%7D%7D%7D
```

Returns an id_token with acrs claim, value=c1.

Solution to 'no 2nd FA' on subsequent requests: logout user!