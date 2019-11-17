using Microsoft.AspNetCore.Mvc;

namespace MVCClient1.Controllers
{
    public class CallBackController: Controller
    {
        public ActionResult Index(string code)
        {
            return Content(code);
        }
    }
}
