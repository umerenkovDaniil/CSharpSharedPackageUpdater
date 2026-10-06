using System.Threading;
using System.Threading.Tasks;

namespace CSharpSharedPackageUpdater.Interfaces
{
	public interface IOp
	{
		string Path { get; set; }
		Task FixAsync(CancellationToken ct);
		Task SaveAsync(CancellationToken ct);
	}
}