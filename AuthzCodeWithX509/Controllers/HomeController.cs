using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Diagnostics;
using AuthzCodeWithX509.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Text.Json;

namespace AuthzCodeWithX509.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly MicrosoftIdentityConsentAndConditionalAccessHandler _consentHandler;
        private readonly IHttpContextAccessor _httpAccessor;

        public HomeController(ILogger<HomeController> logger, 
            MicrosoftIdentityConsentAndConditionalAccessHandler consentHandler,
            IHttpContextAccessor httpAccessor)
        {
            _logger = logger;
            _consentHandler = consentHandler;
            _httpAccessor = httpAccessor;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            // If user's authentication did not involve c1 Authentication Context, re-issue challenge for it
            if (User.Claims.FirstOrDefault(c => (c.Type == "acrs") && c.Value.Split(',').Contains("c1")) == null)
            {
                var claimsRequired = new { id_token = new { acrs = new { essential = true, value = "c1" } } };
                _consentHandler.ChallengeUser(scopes: null, claims: JsonSerializer.Serialize(claimsRequired));
            }
            return View();
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
