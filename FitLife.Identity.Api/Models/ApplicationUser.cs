using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;

namespace FitLife.Identity.Api.Models;

[CollectionName("users")]
public class ApplicationUser : MongoIdentityUser<Guid>
{
    public string FullName { get; set; } = string.Empty;
}