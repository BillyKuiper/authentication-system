using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using authentication_system.Data;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Newtonsoft.Json;
using NPOI.SS.Formula.Functions;

namespace authentication_system.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly DataContext db;
        public AuthenticationController(DataContext db)
        {
            this.db = db;
        }

        [Route("/[controller]/values")]
        [HttpGet]
        public string login([FromHeader]string Authorization)
        {

            TokenController TC = new TokenController();
            string validToken = TC.isExpired(Authorization);
            List<Claim> x = TC.readOut(validToken);
            User u = new User();

            foreach (Claim c in x)
            {
                if (c.Type == "Name")
                {
                    u.name = c.Value;
                }
                if (c.Type == "password")
                {
                    u.password = c.Value;
                }
            }

            var user = from User in db.Users
                       where User.name == u.name && User.password == u.password
                       select User;

            string json = JsonConvert.SerializeObject(user);

            if(json == "[]")
            {
                return "400";
            }
            return json;
        }

        [Route("/[controller]/register")]
        [HttpPost]
        public void register([FromBody] User u)
        {
            db.Users.Add(u);
            db.SaveChanges();
        }

        public void expireRedirect()
        {
            
        }
    }
}
