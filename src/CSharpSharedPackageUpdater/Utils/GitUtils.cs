using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using CSharpSharedPackageUpdater.Exceptions;

namespace CSharpSharedPackageUpdater.Utils
{
	public static class GitUtils
	{
		public static Task CloneAsync(string sshUrl, string workDir)
		{
			const string op = "clone {0}";
			return GitProcessAsync(string.Format(op, sshUrl), workDir);
		}

		public static Task PushAsync(string workDir)
		{
			const string op = "push";
			return GitProcessAsync(op, workDir);
		}

		public static Task PullAsync(string workDir)
		{
			const string op = "pull";
			return GitProcessAsync(op, workDir);
		}

		private static async Task GitProcessAsync(string args, string workDir)
		{
			const string git = "git";

			if (!Directory.Exists(workDir)) throw new DirectoryNotFoundException(workDir);

			var processOptions = new ProcessStartInfo
			{
				FileName = git,
				Arguments = args,
				WorkingDirectory = workDir,
				RedirectStandardError = true,
				RedirectStandardOutput = true,
			};

			using var process = new System.Diagnostics.Process();
			process.StartInfo = processOptions;

			process.Start();
			await process.WaitForExitAsync();

			if (process.ExitCode != 0)
			{
				var errTask = process.StandardError.ReadToEndAsync();
				var stdTask = process.StandardOutput.ReadToEndAsync();

				await Task.WhenAll(errTask, stdTask);
				throw new ProcessException($"{processOptions.FileName} {processOptions.Arguments}", process.ExitCode, errTask.Result, stdTask.Result);
			}
		}
	}
}