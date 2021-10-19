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
using System.IdentityModel.Tokens.Jwt;

namespace authentication_system.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly DataContext db;
        TokenController TC = new TokenController();
        public AuthenticationController(DataContext db)
        {
            this.db = db;
        }

        [Route("/[controller]/login")]
        [HttpGet]
        public string login([FromHeader]string Authorization, [FromBody]User mainUser)
        {
            if(Authorization == null)
            {
                loginNoToken(mainUser.email, mainUser.password);
            }
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

        public string loginNoToken(string email, string password)
        {
            string validToken = TC.nonExistentToken(email, password);
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
            //ToDo: Random Object maken met user en token gegevens
            if (json == "[]")
            {
                return "400";
            }
            return json;
            //always return token
        }

        [Route("/[controller]/register")]
        [HttpPost]
        public string register([FromBody] User u)
        {
            if(u.email == "" || u.name == "" || u.password == "")
            {
                return "400";
            }
            else
            {
                //ToDo: check if inserted data already exitst in database
                //If not excute the following code:
                var x =  TC.CreateToken(u.name, u.password);
                System.Reflection.PropertyInfo pi = x.GetType().GetProperty("Value");
                string token = (String)pi.GetValue(x, null);
                if(token != null)
                {
                    db.Users.Add(u);
                    db.SaveChanges();
                    return token;
                }
                return "400";
            }
         
        }

        public void expireRedirect()
        {
            
        }
    }
}
