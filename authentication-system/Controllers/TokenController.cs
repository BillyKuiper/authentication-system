using authentication_system.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Flurl.Http;
using Newtonsoft.Json;

namespace authentication_system.Controllers
{
    public class TokenController
    {
        private const string SECRET_KEY = "this is my custom Secret key for authnetication";
        public static readonly SymmetricSecurityKey SIGNING_KEY = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TokenController.SECRET_KEY));

        public object CreateToken(string username, string password)
        {
            if(username != password)
            {
                return new ObjectResult(GenerateToken(username, password));
            }
            else
            {
                return new BadRequestResult();
            }
        }

        private object GenerateToken(string username, string password)
        {
            var token = new JwtSecurityToken(
                claims: new Claim[]
                {
                    new Claim("Name", username),
                    new Claim("password", password)
                },
                notBefore: new DateTimeOffset(DateTime.Now).DateTime,
                expires: new DateTimeOffset(DateTime.Now.AddMinutes(60)).DateTime,
                signingCredentials: new SigningCredentials(SIGNING_KEY, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public List<Claim> readOut(string test)
        {
            List<Claim> data = new List<Claim>();
       
            var token = test;
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            foreach(Claim c in jwtSecurityToken.Claims)
            {
                data.Add(c);
            }
            return data;
        }

        public string isExpired(string test)
        {
            string[] split = test.Split(" ");

            var token = split[1];
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);

            if (jwtSecurityToken.ValidFrom > DateTime.UtcNow && jwtSecurityToken.ValidTo < DateTime.UtcNow)
            {
                //is valid
                return split[1];
            }
            else
            {
                //is expired
                List<string> temp = new List<string>();
                User u = new User();

                foreach (Claim c in jwtSecurityToken.Claims)
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
                //Newly generated token when old token was expired
                object newToken = GenerateToken(u.name, u.password);
                string jsonToken = newToken.ToString();
                return jsonToken;
            }
        }

        public string nonExistentToken(string email, string password)
        {
            var x = GenerateToken(email, password);
            return x.ToString();
        }
    }
}
