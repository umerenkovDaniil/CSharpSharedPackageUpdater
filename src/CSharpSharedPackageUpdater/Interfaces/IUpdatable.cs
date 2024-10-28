using System.Xml.Linq;

namespace CSharpSharedPackageUpdater.Interfaces
{
	public interface IUpdatable
	{
		string Path { get; set; }
		XDocument Xml { get; set; }
		void Fix();
		bool Resolved { get; set; }
	}
}