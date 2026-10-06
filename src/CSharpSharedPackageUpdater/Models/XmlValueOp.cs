using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public sealed class XmlValueOp : XmlOp, IOp
	{
		public XElement Node { get; set; }
		public string NewValue { get; set; }

		public XmlValueOp(
			string path,
			XDocument xml,
			XElement node,
			string newValue)
		: base(path, xml)
		{
			Node = node;
			NewValue = newValue;
		}

		public override Task FixAsync(CancellationToken ct)
		{
			Node.SetValue(NewValue);
			return Task.CompletedTask;
		}

		public override string ToString()
		{
			return $"framework {Path} {NewValue}";
		}
	}
}