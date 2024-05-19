using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace AuthenticationClassLibrary.Models
{
    public class User
    {
        public int? UserId { get; set; }
        public string? UserName { get; set; }
        [JsonIgnore]
        public string? Password { get; set; }
        public DateTime? Last_Password_Change { get; set; }
        public bool? isActive { get; set; }
        public int? RoleID { get; set; }

        public bool? MustChangePassword { get; set; }
    }
    public class PasswordChangeModel
    {
        public string Username { get; set; }
        public string NewPassword { get; set; }
    }


}
