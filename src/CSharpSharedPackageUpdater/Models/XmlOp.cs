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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using CSharpSharedPackageUpdater.Interfaces;

namespace CSharpSharedPackageUpdater.Models
{
	public abstract class XmlOp : IOp
	{
		public string Path { get; set; }
		public XDocument Xml { get; set; }

		protected XmlOp(
			string path,
			XDocument xml)
		{
			Path = path;
			Xml = xml;
		}

		public abstract Task FixAsync(CancellationToken ct);

		public async Task SaveAsync(CancellationToken ct)
		{
			await using var fs = File.OpenWrite(Path);

			// unset current content
			fs.SetLength(0);

			await fs.FlushAsync(ct);
			fs.Seek(0, SeekOrigin.Begin);

			await using var xw = XmlWriter.Create(
				fs,
				new XmlWriterSettings
				{
					Indent = true,
					IndentChars = "\t",
					Async = true,
					CloseOutput = true,
					OmitXmlDeclaration = true,
					Encoding = Encoding.UTF8
				});

			await Xml.SaveAsync(xw, ct);
		}
	}
}