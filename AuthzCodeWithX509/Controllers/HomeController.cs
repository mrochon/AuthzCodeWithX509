using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Diagnostics;
using AuthzCodeWithX509.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthzCodeWithX509.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly MicrosoftIdentityConsentAndConditionalAccessHandler _consentHandler;

        public HomeController(ILogger<HomeController> logger, 
            MicrosoftIdentityConsentAndConditionalAccessHandler consentHandler)
        {
            _logger = logger;
            _consentHandler = consentHandler;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            //_consentHandler.ChallengeUser(scopes: null, claims: "c1");
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
