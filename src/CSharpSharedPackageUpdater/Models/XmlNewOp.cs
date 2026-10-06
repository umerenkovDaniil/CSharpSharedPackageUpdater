using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public sealed class XmlNewOp : XmlOp, IOp
	{
		public XElement Parent { get; set; }
		public string Name { get; set; }
		public object? Value { get; set; }
		public Dictionary<string, object?>? Attributes { get; set; }

		public XmlNewOp(
			string path,
			XDocument xml,
			XElement parent,
			string name,
			object? value,
			Dictionary<string, object?>? attributes = null)
			: base(path, xml)
		{
			Parent = parent;
			Name = name;
			Value = value;
			Attributes = attributes;
		}

		public override Task FixAsync(CancellationToken ct)
		{
			var el = new XElement(Name, Value);
			Parent.Add(el);

			if (Attributes != null)
			{
				foreach (var (key, val) in Attributes)
				{
					el.SetAttributeValue(key, val);
				}
			}

			return Task.CompletedTask;
		}

		public override string ToString()
		{
			return $"new element {Path} {Name}";
		}
	}
}