using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using AuthzCodeWithX509.Controllers;
using System.IdentityModel.Tokens.Jwt;

namespace AuthzCodeWithX509
{
    public static class AuthenticationBuilderExtensions
    {
        public static void SetClientAssertion(
            this AuthorizationCodeReceivedContext context, 
            MicrosoftIdentityOptions options)
        {
            var creds = GetCert(options);
            // https://www.rfc-editor.org/rfc/rfc7521#page-10
            var iss = options.ClientId;
            var sub = options.ClientId;
            var aud = $"{options.Instance}{options.TenantId}/oauth2/v2.0/token";
            // var aud = context.TokenEndpointRequest.RequestUri;
            var nonce = "defult";

            IList<System.Security.Claims.Claim> claims = new List<System.Security.Claims.Claim>();
            claims.Add(new System.Security.Claims.Claim("sub", options.ClientId, System.Security.Claims.ClaimValueTypes.String, iss));
            claims.Add(new System.Security.Claims.Claim("nonce", nonce, System.Security.Claims.ClaimValueTypes.String, iss));

            JwtSecurityToken token = new JwtSecurityToken(
                    issuer: iss,
                    audience: aud,
                    claims,
                    DateTime.Now,
                    DateTime.Now.AddMinutes(10),
                    creds);
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

            context.TokenEndpointRequest!.ClientAssertion = jwtHandler.WriteToken(token);
            context.TokenEndpointRequest!.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        }
        private static X509SigningCredentials GetCert(MicrosoftIdentityOptions options)
        {
            if ((options.ClientCertificates != null) && options.ClientCertificates.Any())
            {
                var cert = options.ClientCertificates.First();
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
            }
            throw new Exception("Certificate not found");
        }
    }
}
