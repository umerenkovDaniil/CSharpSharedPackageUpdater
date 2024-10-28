namespace CSharpSharedPackageUpdater.Models
{
	public class BuildResult
	{
		public int Code { get; set; }
		public string[] Vulnerabilities { get; set; }
		public string[] Obsolete { get; set; }
		public string StdOut { get; set; }
		public string StdErr { get; set; }
		public string Name { get; set; }

		public BuildResult()
		{
			Vulnerabilities = [];
			Obsolete = [];

			StdOut = string.Empty;
			StdErr = string.Empty;
			Name = string.Empty;
		}
	}
}