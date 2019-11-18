using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security.Cookies;
using MVCClient1.Models;
using Newtonsoft.Json;

namespace MVCClient1.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IDataProtectionProvider _provider;

        public HomeController(ILogger<HomeController> logger, IDataProtectionProvider provider)
        {
            _logger = logger;
            _provider = provider;
        }

        [Authorize]
        public IActionResult Index()
        {
            var user = HttpContext.User;
            return View();
        }

        public IActionResult DecryptCookie()
        {
            string cookieValue = HttpContext.Request.Cookies[".AspNetCore.Cookies"];

            //Get a data protector to use with either approach
            var dataProtector = _provider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "Cookies", "v2");


            //Get the decrypted cookie as plain text
            UTF8Encoding specialUtf8Encoding = new UTF8Encoding();
            byte[] protectedBytes = Base64UrlTextEncoder.Decode(cookieValue);
            byte[] plainBytes = dataProtector.Unprotect(protectedBytes);
            string plainText = Encoding.ASCII.GetString(plainBytes);
            var myToken = JsonConvert.DeserializeObject(plainText);


            //Get the decrypted cookie as a Authentication Ticket
            TicketDataFormat ticketDataFormat = new TicketDataFormat(dataProtector);
            AuthenticationTicket ticket = ticketDataFormat.Unprotect(cookieValue);

            return View();
        }

        public async Task<IActionResult> Privacy()
        {
            await HttpContext.SignOutAsync();
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
