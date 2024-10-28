using System;
using CSharpSharedPackageUpdater.Models;

namespace CSharpSharedPackageUpdater.Exceptions
{
	public class ProcessException : Exception
	{
		public int ExitCode { get; set; }
		public string Name { get; set; }
		public string StdErr { get; set; }
		public string StdOut { get; set; }
		public string? Reason { get; set; }

		public ProcessException(BuildResult r, string? reason = null)
			: this(r.Name, r.Code, r.StdErr, r.StdOut, reason)
		{
		}

		public ProcessException(string name, int exitCode, string stdErr, string stdOut, string? reason = null)
			: base($"process {name} failed with {exitCode}\nreason: {reason}\nstderr: {stdErr}\n stdout:{stdOut}")
		{
			ExitCode = exitCode;
			Name = name;
			StdErr = stdErr;
			StdOut = stdOut;
			Reason = reason;
		}
	}
}