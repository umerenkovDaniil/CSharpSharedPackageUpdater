using NuGet.Versioning;

namespace CSharpSharedPackageUpdater.Models
{
	public class NugetPackage
	{
		public string Name { get; set; }
		public NuGetVersion Version { get; set; }

		public NugetPackage(string name, NuGetVersion version)
		{
			Name = name;
			Version = version;
		}

		public override string ToString()
		{
			return Name;
		}
	}
}