using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public sealed class XmlDeleteOp : XmlOp, IOp
	{
		public XElement Node { get; set; }

		public XmlDeleteOp(
			string path,
			XDocument xml,
			XElement node)
			: base(path, xml)
		{
			Node = node;
		}

		public override Task FixAsync(CancellationToken ct)
		{
			Node.Remove();
			return Task.CompletedTask;
		}

		public override string ToString()
		{
			return $"delete element {Path} {Node.Name}";
		}
	}
}