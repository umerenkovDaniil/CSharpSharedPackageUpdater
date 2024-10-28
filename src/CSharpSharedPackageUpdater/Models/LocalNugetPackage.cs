using System.Collections.Generic;
using System.Xml.Linq;
using NuGet.Versioning;

namespace CSharpSharedPackageUpdater.Models
{
	public sealed class LocalNugetPackage : NugetPackage
	{
		public string ProjPath { get; set; }
		public XDocument Xml { get; set; }
		public Dictionary<string, Dependency> Dependencies { get; set; }
		public XElement VersionElement { get; set; }

		public LocalNugetPackage(string name, string projPath, XDocument xml, NuGetVersion version, XElement versionElement)
			: base(name, version)
		{
			ProjPath = projPath;
			Xml = xml;
			VersionElement = versionElement;
			Dependencies = new();
		}
	}
}