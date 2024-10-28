using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;
using NuGet.Versioning;

namespace CSharpSharedPackageUpdater.Models
{
	public sealed class Mismatch : Dependency, IUpdatable
	{
		public string Path { get; set; }
		public XDocument Xml { get; set; }
		public bool Resolved { get; set; }

		public Mismatch(
			string name,
			string path,
			NuGetVersion version,
			NugetPackage target,
			XElement node,
			XDocument xml)
			: base(name, version, node)
		{
			Path = path;
			Target = target;
			Xml = xml;
		}

		public void Fix()
		{
			Node.SetAttributeValue("Version", Target.Version);
		}

		public override string ToString()
		{
			return $"mismatch {Path} {Target.Name} {Version} {Target.Version}";
		}
	}
}