using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public sealed class Framework : IUpdatable
	{
		public string Value { get; set; }
		public string Path { get; set; }
		public XDocument Xml { get; set; }
		public XElement Node { get; set; }
		public string Target { get; set; }
		public bool Resolved { get; set; }

		public Framework(
			string value,
			string path,
			XDocument xml,
			XElement node,
			string target)
		{
			Value = value;
			Path = path;
			Xml = xml;
			Node = node;
			Target = target;
		}

		public void Fix()
		{
			Node.SetValue(Target);
		}

		public override string ToString()
		{
			return $"framework {Path} {Value} {Target}";
		}
	}
}