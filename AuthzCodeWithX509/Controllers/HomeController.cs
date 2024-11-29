using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Diagnostics;
using AuthzCodeWithX509.Models;

namespace AuthzCodeWithX509.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        MicrosoftIdentityConsentAndConditionalAccessHandler _consentHandler;

        public HomeController(ILogger<HomeController> logger, MicrosoftIdentityConsentAndConditionalAccessHandler consentHandler)
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
            // https://github.com/Azure-Samples/ms-identity-ca-auth-context/blob/main/TodoListClient/Controllers/TodoListController.cs
            _consentHandler.ChallengeUser(new string[] { "user.read" }, "c1");
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
