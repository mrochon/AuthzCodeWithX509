using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using AuthzCodeWithX509.Controllers;
using Microsoft.Identity.Abstractions;

namespace AuthzCodeWithX509.Services
{
    public static class TokenBuilder
    {
        private static X509SigningCredentials GetCert()
        {
            if ((options.ClientCertificates != null) && options.ClientCertificates.Any())
            {
                var cert = options.ClientCertificates.First();
                var creds = new Lazy<X509SigningCredentials>(() =>
                {
                    X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    certStore.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection certCollection = certStore.Certificates.Find(
                                                X509FindType.FindByThumbprint,
                                                cert.CertificateThumbprint!,
                                                false);
                    // Get the first cert with the thumb-print
                    if (certCollection.Count > 0)
                    {
                        return new X509SigningCredentials(certCollection[0]);
                    }
                    throw new Exception("Certificate not found");
                });
            }
            throw new Exception("Certificate not found");
        }
        public static string Build(MicrosoftIdentityOptions options)
        {
            // https://www.rfc-editor.org/rfc/rfc7521#page-10
            var iss = options.ClientId;
            var sub = options.ClientId;
            var aud = $"{options.Instance}{options.TenantId}/oauth2/v2.0/token";
            var nonce = "";
            var assertion_type = "";

            IList<System.Security.Claims.Claim> claims = new List<System.Security.Claims.Claim>();
            claims.Add(new System.Security.Claims.Claim("sub", options.ClientId, System.Security.Claims.ClaimValueTypes.String, iss));
            claims.Add(new System.Security.Claims.Claim("nonce", nonce, System.Security.Claims.ClaimValueTypes.String, iss));

            // Create the token
            JwtSecurityToken token = new JwtSecurityToken(
                    issuer:iss,
                    audience:options.ClientId,
                    claims,
                    DateTime.Now,
                    DateTime.Now.AddMinutes(10),
                    HomeController.SigningCredentials.Value);

            // Get the representation of the signed token
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

            return jwtHandler.WriteToken(token);
        }
    }
}
