using NuGet.Configuration;

namespace CSharpSharedPackageUpdater.Models
{
	public class SharedPackage
	{
		public string Path { get; set; }
		public bool IncludePrerelease { get; set; }
		public int MaxPageSize { get; set; } = 100;
		public bool AutoResolve { get; set; }
		public PackageSourceCredential Credentials { get; set; }

		public SharedPackage(string path, PackageSourceCredential credentials)
		{
			Path = path;
			Credentials = credentials;
			AutoResolve = true;
		}
	}
}