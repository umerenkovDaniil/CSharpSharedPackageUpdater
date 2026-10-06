/*
 *
 * Copyright (c) 2023 TenderHub LLC. All rights reserved
 *
 * This software is the confidential and proprietary information of
 * TenderHub LLC ("Confidential Information"). You shall not disclose
 * such Confidential Information.
 *
 */

using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public class FileOp : IOp
	{
		public string Path { get; set; }
		public string Target { get; set; }
		public bool Exists { get; set; }

		public FileOp(string path, string target, bool exists)
		{
			Path = path;
			Target = target;
			Exists = exists;
		}

		public Task FixAsync(CancellationToken ct)
		{
			return Task.CompletedTask;
		}

		public Task SaveAsync(CancellationToken ct)
		{
			if (Exists) File.Delete(Path);
			File.Copy(Target, Path);

			return Task.CompletedTask;
		}
	}
}