using System.Xml.Linq;
using NuGet.Versioning;

namespace CSharpSharedPackageUpdater.Models
{
	public class Dependency
	{
		public string Name { get; set; }
		public NuGetVersion Version { get; set; }
		public XElement Node { get; set; }
		public NugetPackage Target { get; set; }

		public Dependency(string name, NuGetVersion version, XElement node)
		{
			Name = name;
			Version = version;
			Node = node;

			Target = null!;
		}

		public void Deconstruct(out string name, out NuGetVersion version, out XElement node, out NugetPackage target)
		{
			name = Name;
			version = Version;
			node = Node;
			target = Target;
		}

		public void Deconstruct(out string name, out NuGetVersion version, out XElement node)
		{
			name = Name;
			version = Version;
			node = Node;
		}
	}
}