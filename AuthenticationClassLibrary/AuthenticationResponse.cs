using AuthenticationClassLibrary.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationClassLibrary
{
    public class AuthenticationResponse
    {
        public int? UserId { get; set; }
        public string? FullName { get; set; }
        public string? Token { get; set; }

        public bool MustChangePassword { get; set; }    

        public AuthenticationResponse(User? userDetail, string? token)
        {
            UserId = userDetail.UserId;
            FullName = userDetail.UserName;
            Token = token;
            MustChangePassword = userDetail?.Last_Password_Change == null;
           
        }
        // Output JSON - { "Fullname":"xxx", "UserId": "99", "Token": "ENCTOKEN" } == This is the Output JSON sent to the Client.
        public AuthenticationResponse() { }
    }
}
