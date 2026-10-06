using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public class XmlAttributeOp : XmlOp, IOp
	{
		public XElement Node { get; set; }
		public string AttributeName { get; set; }
		public object? AttributeValue { get; set; }

		public XmlAttributeOp(
			string path,
			XDocument xml,
			XElement node,
			string attributeName,
			object? attributeValue)
		: base(path, xml)
		{
			Node = node;
			AttributeName = attributeName;
			AttributeValue = attributeValue;
		}

		public override Task FixAsync(CancellationToken ct)
		{
			Node.SetAttributeValue(AttributeName, AttributeValue);
			return Task.CompletedTask;
		}

		public override string ToString()
		{
			return $"mismatch {Path} {AttributeName} {AttributeValue}";
		}
	}
}