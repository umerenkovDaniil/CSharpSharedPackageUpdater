using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using CSharpSharedPackageUpdater.Exceptions;
using CSharpSharedPackageUpdater.Extensions;
using CSharpSharedPackageUpdater.Interfaces;
using CSharpSharedPackageUpdater.Models;
using CSharpSharedPackageUpdater.Utils;
using LibGit2Sharp;
using Microsoft.Extensions.Logging;
using NuGet.Common;
using NuGet.Configuration;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Versioning;
using ILogger = Microsoft.Extensions.Logging.ILogger;
using LogLevel = NuGet.Common.LogLevel;
using NullLogger = Microsoft.Extensions.Logging.Abstractions.NullLogger;
using Repository = LibGit2Sharp.Repository;

namespace CSharpSharedPackageUpdater
{
	public class PackageUpdater : IDisposable
	{
		private const string PROPS = "Directory.Build.props";
		private const int NUGET_MAX_PAGE_SIZE = 1000;
		private const int NUGET_MAX_SKIP = 3000;

		public string? ReposDir { get; set; }
		public SharedPackage[] Shared { get; set; }
		public ILogger Logger { get; set; }
		public string Nuget { get; set; } = "https://api.nuget.org/v3/index.json";
		public string[] NugetPackages { get; set; }
		public bool AutoResolve { get; set; } = true;
		public bool AutoCommit { get; set; } = true;
		public string Branch { get; set; } = "development";
		public string[] ReposExclude { get; set; }
		public string[] DirtyFilesSkip { get; set; }
		public string[] ObsoleteWarnings { get; set; }
		public string[] VulnerabilityWarnings { get; set; }
		public string TargetFramework { get; set; } = $"net{Environment.Version.Major}.{Environment.Version.Minor}";
		public Signature? Sig { get; set; }
		public string CommitMessage { get; set; } = "autoupdate packages";

		private readonly ConcurrentDictionary<string, Repository> _repos;
		private NugetLogWrapper? _nugetLogger;

		private bool _disposed;

		private NugetLogWrapper NugetLogger
		{
			get
			{
				_nugetLogger ??= new NugetLogWrapper(Logger);
				return _nugetLogger;
			}
		}

		public PackageUpdater()
		{
			_repos = new ConcurrentDictionary<string, Repository>();
			Shared = [];
			Logger = NullLogger.Instance;
			NugetPackages = [];
			ReposExclude = [];
			DirtyFilesSkip = [];
			ObsoleteWarnings = [];
			VulnerabilityWarnings = [];
		}

		/// <summary>
		/// Find, set all to dev, query versions, update all.
		/// </summary>
		/// <returns>Task.</returns>
		public async Task FullAsync()
		{
			var all = FindExistingRepos();
			await SetBranchAsync(all, Branch);

			var packages = await GetPackagesAsync();
			await UpdateReposAsync(all, packages);
		}

		/// <summary>
		/// Build all solutions.
		/// </summary>
		/// <returns>Build results for all solutions.</returns>
		public async Task<BuildResult[]> BuildAllAsync()
		{
			var repos = FindExistingRepos();
			var res = new BuildResult[repos.Length];

			await repos.ForEachIndexedAsync(async i => res[i] = await BuildAsync(repos[i]));
			return res;
		}

		/// <summary>
		/// Sets target branch for all non-dirty repos.
		/// </summary>
		/// <param name="repos">Repos.</param>
		/// <param name="branch">Target branch.</param>
		/// <exception cref="AggregateException">Container for dirty repos.</exception>
		/// <returns>Task.</returns>
		public async Task SetBranchAsync(string[] repos, string branch)
		{
			var exceptions = new ConcurrentBag<Exception>();

			await repos.ForEachAsync(async r =>
			{
				var dirty = await CheckAndPullAsync(r, branch);
				if (dirty) exceptions.Add(new InvalidOperationException($"{Path.GetFileName(r)} dirty"));
			});

			if (exceptions.Count != 0) throw new AggregateException(exceptions);
		}

		/// <summary>
		/// Update repos.
		/// </summary>
		/// <param name="repos">Repos dirs.</param>
		/// <param name="packages">Packages versions.</param>
		/// <param name="token">Cancellation token.</param>
		/// <exception cref="NoNullAllowedException">Some required options are null.</exception>
		/// <exception cref="XmlException">Repo xml invalid.</exception>
		/// <exception cref="InvalidOperationException">Invalid framework or xml.</exception>
		/// <exception cref="AggregateException">Container for multiple versions exceptions.</exception>
		/// <exception cref="ManualRequiredException">Manual commit required.</exception>
		/// <returns>Task.</returns>
		public async Task UpdateReposAsync(string[] repos, IDictionary<string, NugetPackage> packages, CancellationToken token = default)
		{
			if (AutoCommit && Sig == null) throw new NoNullAllowedException("git signature is null");

			using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);

			var ct = cts.Token;
			var allUpdates = new ConcurrentDictionary<string, ConcurrentBag<(string, IUpdatable[])>>();
			var exceptions = new ConcurrentBag<Exception>();

			await repos.ForEachAsync(
				async dir =>
				{
					ct.ThrowIfCancellationRequested();

					// checking build.props
					var (ex, mismatches) = await CheckPropsAsync(dir, packages, ct);
					if (mismatches.Length != 0)
					{
						allUpdates.AddOrUpdate(
							dir,
							_ => [(PROPS, mismatches)],
							(_, l) =>
							{
								l.Add((PROPS, mismatches));
								return l;
							});
					}

					if (ex.Length != 0)
					{
						foreach (var e in ex)
						{
							exceptions.Add(e);
						}
					}

					foreach (var file in Directory.GetFiles(dir, "*.csproj", SearchOption.AllDirectories))
					{
						await using var fs = File.OpenRead(file);
						var proj = await XDocument.LoadAsync(fs, LoadOptions.None, CancellationToken.None);
						if (proj.Root == null) throw new XmlException(file);

						var fileName = new DirectoryInfo(file).Name;
						var localMismatches = new List<IUpdatable>();

						// framework check
						var frameworks = proj.Root.Descendants("TargetFramework").ToArray();
						if (frameworks.Length != 1) throw new InvalidOperationException($"{fileName} invalid num of frameworks");

						var fr = new Framework(frameworks[0].Value, file, proj, frameworks[0], TargetFramework);
						if (!TargetFramework.Equals(fr.Value, StringComparison.InvariantCultureIgnoreCase))
						{
							Logger.LogDebug("{Fr}", fr);
							localMismatches.Add(fr);
						}

						// versions check
						foreach (var (n, v, node) in AllDependencies(proj, file))
						{
							if (!packages.TryGetValue(n, out var p)) continue;

							if (v > p.Version)
							{
								var e = new InvalidOperationException($"{dir} {n} version greater than serv ({v} > {p.Version})");
								Logger.LogError(e, "error");
								exceptions.Add(e);

								continue;
							}

							if (v != p.Version)
							{
								var m = new Mismatch(n, file, v, p, node, proj);
								Logger.LogDebug("{M}", m);
								localMismatches.Add(m);
							}
						}

						if (localMismatches.Count != 0)
						{
							var arr = localMismatches.ToArray();

							allUpdates.AddOrUpdate(
								dir,
								_ => [(fileName, arr)],
								(_, l) =>
								{
									l.Add((fileName, arr));
									return l;
								});
						}
					}
				},
				token: ct);

			if (exceptions.Count != 0) throw new AggregateException(exceptions);

			ct.ThrowIfCancellationRequested();

			if (allUpdates.IsEmpty)
			{
				Logger.LogDebug("no updates");
				return;
			}

			if (!allUpdates.IsEmpty)
			{
				if (!AutoResolve) throw new ManualRequiredException("mismatches found", allUpdates);
				await allUpdates.ForEachAsync(
					async p =>
					{
						ct.ThrowIfCancellationRequested();

						foreach (var (_, updates) in p.Value)
						{
							await ResolveUpdatesAsync(updates, ct);
						}

						if (!AutoCommit) return;

						var build = await BuildAsync(p.Key);
						ProcessException? e = null;

						if (build.Code != 0)
						{
							e = new ProcessException(build);
						}
						else if (build.Vulnerabilities.Length != 0)
						{
							e = new ProcessException(build, $"vulnerabilities found: {string.Join(' ', build.Vulnerabilities)}");
						}
						else if (build.Obsolete.Length != 0)
						{
							e = new ProcessException(build, $"obsolete found: {string.Join(' ', build.Obsolete)}");
						}

						if (e != null)
						{
							Logger.LogError(e, "error");
							exceptions.Add(e);

							return;
						}

						await PushUpvAsync(p.Key);
					},
					token: ct);
			}
		}

		private async Task PushUpvAsync(string dir)
		{
			if (Sig == null) throw new NoNullAllowedException("git signature is null");

			using var repo = new Repository(dir);

			var status = repo.RetrieveStatus();
			var toCommit = status
				.Modified
				.Select(x => x.FilePath)
				.ToArray();

			Commands.Stage(repo, toCommit);

			repo.Commit(CommitMessage, Sig, Sig, new CommitOptions
			{
				AllowEmptyCommit = false,
				PrettifyMessage = true
			});

			await GitUtils.PushAsync(dir);
			Logger.LogDebug("{Dir} pushed", dir);
		}

		public string[] FindExistingRepos()
		{
			if (string.IsNullOrWhiteSpace(ReposDir)) throw new NoNullAllowedException("reposDir");
			if (!Directory.Exists(ReposDir)) throw new DirectoryNotFoundException("reposDir");

			var allDirs = Directory.GetDirectories(ReposDir);
			var result = new List<string>(allDirs.Length);

			foreach (var d in allDirs)
			{
				if (Directory.GetFiles(d, "*.sln").Length == 0) continue;
				if (Directory.GetDirectories(d, ".git").Length == 0) continue;

				var info = new DirectoryInfo(d);
				if (ReposExclude?.Contains(info.Name) == true) continue;

				result.Add(d);
			}

			return result.ToArray();
		}

		/// <summary>
		/// Get packages versions.
		/// </summary>
		/// <param name="token">Cancellation token.</param>
		/// <returns>Packages versions.</returns>
		/// <exception cref="DirectoryNotFoundException">Local package dir not found.</exception>
		/// <exception cref="InvalidOperationException">Too many nuget packages or some repos are dirty.</exception>
		/// <exception cref="NotFoundException">Nuget package not found.</exception>
		/// <exception cref="XmlException">Local package xml invalid.</exception>
		/// <exception cref="AggregateException">Container for multiple versions exceptions.</exception>
		/// <exception cref="ManualRequiredException">Manual commit required.</exception>
		public async Task<IDictionary<string, NugetPackage>> GetPackagesAsync(CancellationToken token = default)
		{
			foreach (var shared in Shared)
			{
				if (!Directory.Exists(shared.Path))
				{
					throw new DirectoryNotFoundException(shared.Path);
				}
			}

			using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
			var ct = cts.Token;

			var sharedVersions = new ConcurrentDictionary<string, NuGetVersion>();
			var allProj = new ConcurrentDictionary<string, NugetPackage>();
			var localProj = new ConcurrentDictionary<string, LocalNugetPackage>();

			Task nugetTask;

			// query private nugets
			var sharedTask = Shared.ForEachAsync(
				async shared =>
				{
					ct.ThrowIfCancellationRequested();

					var dirty = await CheckAndPullAsync(shared.Path, Branch);
					if (dirty)
					{
						await cts.CancelAsync();
						throw new InvalidOperationException($"{shared.Path} dirty");
					}

					var packageSource = new PackageSource(shared.Credentials.Source)
					{
						Credentials = shared.Credentials
					};

					var rep = NuGet.Protocol.Core.Types.Repository.Factory.GetCoreV3(packageSource);
					var resource = await rep.GetResourceAsync<PackageSearchResource>(ct);
					var filter = new SearchFilter(shared.IncludePrerelease);

					var skip = 0;
					var total = 0;
					bool @break;

					do
					{
						var search = await resource.SearchAsync(
							string.Empty,
							filter,
							skip,
							shared.MaxPageSize,
							NugetLogger,
							ct);

						var i = 0;
						foreach (var package in search)
						{
							i++;
							if (string.IsNullOrEmpty(package.Identity.Version?.OriginalVersion)) continue;

							total++;
							sharedVersions[package.Title] = NuGetVersion.Parse(package.Identity.Version.OriginalVersion);
						}

						@break = i == 0 || i % shared.MaxPageSize != 0;
						skip += i;
					}
					while (!@break);

					Logger.LogDebug("{Source} found {Total} packages", shared.Credentials.Source, total);
				},
				token: cts.Token);

			if (NugetPackages.Length != 0)
			{
				if (NugetPackages.Length > NUGET_MAX_SKIP + NUGET_MAX_PAGE_SIZE)
				{
					await cts.CancelAsync();
					throw new InvalidOperationException("too many nuget packages");
				}

				// query nuget.org
				nugetTask = Task.Run(
					async () =>
					{
						var rep = NuGet.Protocol.Core.Types.Repository.Factory.GetCoreV3(Nuget);
						var resource = await rep.GetResourceAsync<PackageSearchResource>(ct);
						var filter = new SearchFilter(false);

						// splitting request into parallel chunks by page size
						var chunks = NugetPackages.Chunk(NUGET_MAX_PAGE_SIZE).ToArray();
						await chunks.ForEachIndexedAsync(
							async i =>
							{
								ct.ThrowIfCancellationRequested();

								// keyword search
								var search = await resource.SearchAsync(
									$"PackageId:{string.Join(" PackageId:", chunks[i])}",
									filter,
									i * NUGET_MAX_PAGE_SIZE,
									NUGET_MAX_PAGE_SIZE,
									NugetLogger,
									ct);

								foreach (var p in search)
								{
									if (string.IsNullOrEmpty(p.Identity.Version.OriginalVersion)) continue;
									allProj.TryAdd(p.Identity.Id, new NugetPackage(p.Title, NuGetVersion.Parse(p.Identity.Version.OriginalVersion)));
								}
							},
							token: ct);

						var notFound = NugetPackages.Except(allProj.Keys).ToArray();
						if (notFound.Length != 0)
						{
							await cts.CancelAsync();
							throw new NotFoundException($"nuget package not found: {string.Join(", ", notFound)}");
						}

						Logger.LogDebug("nuget found all {Count} packages", allProj.Count);
					},
					cts.Token);
			}
			else nugetTask = Task.CompletedTask;

			await Task.WhenAll(nugetTask, sharedTask);
			cts.Token.ThrowIfCancellationRequested();

			// processing local dirs
			await Shared.ForEachAsync(
				async shared =>
				{
					ct.ThrowIfCancellationRequested();

					foreach (var file in Directory.GetFiles(shared.Path, "*.csproj", SearchOption.AllDirectories))
					{
						await using var fs = File.OpenRead(file);
						var proj = await XDocument.LoadAsync(fs, LoadOptions.None, CancellationToken.None);
						if (proj.Root == null)
						{
							await cts.CancelAsync();
							throw new XmlException($"invalid xml {file}");
						}

						var isPackable = bool.TryParse(proj.Root.Descendants("IsPackable").FirstOrDefault()?.Value, out var b) && b;
						if (!isPackable) continue;

						var packageId = proj.Root.Descendants("PackageId").FirstOrDefault()?.Value;
						if (string.IsNullOrEmpty(packageId)) continue;

						var version = proj.Root.Descendants("PackageVersion").FirstOrDefault();
						if (string.IsNullOrEmpty(version?.Value)) continue;

						localProj[packageId] = new LocalNugetPackage(packageId, file, proj, NuGetVersion.Parse(version.Value), version);
						allProj[packageId] = localProj[packageId];
					}
				},
				token: ct);

			cts.Token.ThrowIfCancellationRequested();

			var propsMismatches = new ConcurrentDictionary<SharedPackage, IUpdatable[]>();
			var exceptions = new ConcurrentBag<Exception>();

			// check local build.props
			await Shared.ForEachAsync(
				async p =>
				{
					ct.ThrowIfCancellationRequested();

					var (ex, updates) = await CheckPropsAsync(p.Path, allProj, ct);

					if (updates.Length != 0) propsMismatches.TryAdd(p, updates);
					foreach (var e in ex)
					{
						exceptions.Add(e);
					}
				},
				token: ct);

			if (exceptions.Count != 0) throw new AggregateException(exceptions);
			cts.Token.ThrowIfCancellationRequested();

			// local build.props resolve
			if (propsMismatches.Count != 0)
			{
				if (AutoResolve)
				{
					await propsMismatches
						.ForEachAsync(
							async p =>
							{
								ct.ThrowIfCancellationRequested();
								await ResolveUpdatesAsync(p.Value, ct);
							},
							token: cts.Token);
				}

				throw new ManualRequiredException("commit/resolve and repeat", propsMismatches);
			}

			ct.ThrowIfCancellationRequested();

			// ensuring local versions are equal to the external nugets
			foreach (var (name, proj) in localProj)
			{
				if (!sharedVersions.TryGetValue(name, out var version))
				{
					var e = new KeyNotFoundException($"{name} no nuget version");
					Logger.LogError(e, "error");
					exceptions.Add(e);

					continue;
				}

				if (version != proj.Version)
				{
					var e = new VersionNotFoundException($"{name} version mismatch with server {proj.Version} - {version}");
					Logger.LogError(e, "error");
					exceptions.Add(e);

					break;
				}
			}

			if (exceptions.Count != 0) throw new AggregateException(exceptions);

			// building a dependency tree
			foreach (var (name, proj) in localProj)
			{
				foreach (var (n, v, node) in AllDependencies(proj.Xml, proj.ProjPath))
				{
					if (allProj.TryGetValue(n, out var p))
					{
						if (v > p.Version)
						{
							var e = new VersionNotFoundException($"{name} {n} greater than existing ({v} > {p.Version})");
							Logger.LogError(e, "error");
							exceptions.Add(e);

							continue;
						}

						proj.Dependencies[n] = new Dependency(n, v, node)
						{
							Target = p
						};
					}
				}
			}

			if (exceptions.Count != 0) throw new AggregateException(exceptions);

			var mismatches = new Dictionary<LocalNugetPackage, IUpdatable[]>();
			var mBuffer = new List<IUpdatable>();

			// mismatches with the external nugets
			foreach (var (_, proj) in localProj)
			{
				foreach (var (_, (n, v, node, target)) in proj.Dependencies)
				{
					if (target.Version != v)
					{
						var m = new Mismatch(n, proj.ProjPath, v, target, node, proj.Xml);
						Logger.LogDebug("{M}", m);

						mBuffer.Add(m);
					}
				}

				if (mBuffer.Count != 0)
				{
					mismatches[proj] = mBuffer.ToArray();
					mBuffer.Clear();
				}
			}

			if (mismatches.Count != 0)
			{
				if (AutoResolve)
				{
					await mismatches
						.ForEachAsync(
							async p =>
							{
								ct.ThrowIfCancellationRequested();
								await ResolveUpdatesAsync(p.Value, ct);
							},
							token: cts.Token);
				}

				throw new ManualRequiredException("commit/resolve and repeat", propsMismatches);
			}

			foreach (var (_, val) in allProj)
			{
				Logger.LogDebug("{Name} {Version}", val.Name, val.Version);
			}

			return allProj;
		}

		/// <summary>
		/// Resolves updates.
		/// </summary>
		/// <param name="updates">Updates.</param>
		/// <param name="token">Cancellation token.</param>
		/// <returns>Task.</returns>
		public async Task ResolveUpdatesAsync(IUpdatable[] updates, CancellationToken token = default)
		{
			if (updates.Length == 0) return;

			foreach (var u in updates)
			{
				u.Fix();
				u.Resolved = true;
				Logger.LogDebug("{U} resolved", u);
			}

			await using var fs = File.OpenWrite(updates[0].Path);

			// unset current content
			fs.SetLength(0);

			await fs.FlushAsync(token);
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

			await updates[0].Xml.SaveAsync(xw, token);
			Logger.LogDebug("{Path} resolved", updates[0].Path);
		}

		/// <summary>
		/// Checkout targeted branch if not dirty.
		/// </summary>
		/// <param name="dir">Path to the sln dir.</param>
		/// <param name="branch">Target branch.</param>
		/// <returns>True if repo is dirty.</returns>
		/// <exception cref="DirectoryNotFoundException">Sln dir not found.</exception>
		public async Task<bool> CheckAndPullAsync(string dir, string branch)
		{
			if (!Directory.Exists(dir)) throw new DirectoryNotFoundException(dir);

			var repo = GetRepo(dir);
			var diffs = repo.Diff.Compare<TreeChanges>();
			var dirtyToSkip = new HashSet<string>(DirtyFilesSkip, StringComparer.InvariantCultureIgnoreCase);

			if (diffs.Any(e => !dirtyToSkip.Contains(Path.GetFileName(e.Path))))
			{
				return true;
			}

			Commands.Checkout(repo, branch);

			await GitUtils.PullAsync(dir);
			Logger.LogDebug("{Dir} {Branch} pulled", dir, branch);
			return false;
		}

		/// <summary>
		/// Checking Directory.build.props for sln.
		/// </summary>
		/// <param name="dir">Path to the sln dir.</param>
		/// <param name="packages">Packages versions.</param>
		/// <param name="token">Cancellation token.</param>
		/// <returns>Versions exceptions and needed updates.</returns>
		/// <exception cref="DirectoryNotFoundException">Sln dir not found.</exception>
		/// <exception cref="XmlException">Props xml invalid.</exception>
		public async Task<(Exception[], IUpdatable[])> CheckPropsAsync(string dir, IDictionary<string, NugetPackage> packages, CancellationToken token = default)
		{
			if (!Directory.Exists(dir)) throw new DirectoryNotFoundException(dir);

			var props = Path.Combine(dir, PROPS);
			if (!File.Exists(props)) return ([], []);

			await using var fs = File.OpenRead(props);
			var proj = await XDocument.LoadAsync(fs, LoadOptions.None, token);

			token.ThrowIfCancellationRequested();
			if (proj.Root == null) throw new XmlException(props);

			var result = new List<IUpdatable>();
			var exceptions = new List<Exception>();

			foreach (var (n, v, node) in AllDependencies(proj, props))
			{
				Exception? e = null;

				if (!packages.TryGetValue(n, out var package))
				{
					e = new KeyNotFoundException($"props for {Path.GetFileName(dir)} - {n} not found");
				}
				else if (v > package.Version)
				{
					e = new VersionNotFoundException($"props for {Path.GetFileName(dir)} - {n} version {v} greater than {package.Version}");
				}

				if (e != null)
				{
					Logger.LogError(e, "error");
					exceptions.Add(e);

					continue;
				}

				if (v < package!.Version)
				{
					var m = new Mismatch(n, props, v, package, node, proj);
					Logger.LogDebug("{M}", m);
					result.Add(m);
				}
			}

			return (exceptions.ToArray(), result.ToArray());
		}

		/// <summary>
		/// Build sln via dotnet process.
		/// </summary>
		/// <param name="dir">Path to the sln dir.</param>
		/// <param name="onData">Event on stdOut.</param>
		/// <param name="onErr">Event on stdErr.</param>
		/// <returns>Process result.</returns>
		/// <exception cref="DirectoryNotFoundException">Sln dir not found.</exception>
		public async Task<BuildResult> BuildAsync(string dir, DataReceivedEventHandler? onData = null, DataReceivedEventHandler? onErr = null)
		{
			if (!Directory.Exists(dir)) throw new DirectoryNotFoundException(dir);
			using var process = new Process();

			process.StartInfo = new ProcessStartInfo
			{
				FileName = "dotnet",
				Arguments = $"build {dir}",
				RedirectStandardError = true,
				RedirectStandardOutput = true,
				StandardErrorEncoding = Encoding.UTF8,
				StandardOutputEncoding = Encoding.UTF8
			};

			var obsolete = new List<string>();
			var vulnerability = new List<string>();
			var sbErr = new StringBuilder();
			var sbOut = new StringBuilder();

			process.OutputDataReceived += (sender, args) =>
			{
				onData?.Invoke(sender, args);

				if (string.IsNullOrEmpty(args.Data)) return;

				obsolete.AddRange(ObsoleteWarnings.Where(x => args.Data.Contains(x, StringComparison.InvariantCultureIgnoreCase)));
				vulnerability.AddRange(VulnerabilityWarnings.Where(x => args.Data.Contains(x, StringComparison.InvariantCultureIgnoreCase)));

				sbOut.AppendLine(args.Data);
			};

			process.ErrorDataReceived += (sender, args) =>
			{
				onErr?.Invoke(sender, args);
				sbErr.AppendLine(args.Data);
			};

			process.Start();
			process.BeginOutputReadLine();
			process.BeginErrorReadLine();

			await process.WaitForExitAsync();

			Logger.LogDebug("{Dir} built", dir);

			return new BuildResult
			{
				Code = process.ExitCode,
				Obsolete = obsolete.ToArray(),
				Vulnerabilities = vulnerability.ToArray(),
				StdErr = sbErr.ToString(),
				StdOut = sbOut.ToString(),
				Name = $"{process.StartInfo.FileName} {process.StartInfo.Arguments}"
			};
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (_disposed) return;
			if (disposing)
			{
				foreach (var (_, r) in _repos)
				{
					r.Dispose();
				}
			}

			_disposed = true;
		}

		private Repository GetRepo(string dir)
		{
			if (!Directory.Exists(dir)) throw new DirectoryNotFoundException(dir);

			var name = Path.GetFileName(dir);
			if (!_repos.TryGetValue(name, out var repo))
			{
				repo = new Repository(dir);
				_repos[name] = repo;
			}

			return repo;
		}

		private static IEnumerable<Dependency> AllDependencies(XDocument el, string @ref)
		{
			if (el.Root == null) throw new NoNullAllowedException("xml el root");
			return AllDependencies(el.Root!, @ref);
		}

		private static IEnumerable<Dependency> AllDependencies(XElement el, string @ref)
		{
			foreach (var item in el.Descendants("PackageReference"))
			{
				if (item.Name.LocalName != "PackageReference") continue;

				var include = item.Attribute("Include");
				if (string.IsNullOrEmpty(include?.Value)) throw new InvalidOperationException($"{@ref} include attribute not found");

				var version = item.Attribute("Version");
				if (string.IsNullOrEmpty(version?.Value)) throw new InvalidOperationException($"{@ref} value attribute not found");

				yield return new Dependency(include.Value, NuGetVersion.Parse(version.Value), item);
			}
		}

		private sealed class NugetLogWrapper : NuGet.Common.ILogger
		{
			private readonly ILogger _logger;

			public NugetLogWrapper(ILogger logger)
			{
				_logger = logger;
			}

			public void LogDebug(string data)
			{
				_logger.LogDebug("{Data}", data);
			}

			public void LogVerbose(string data)
			{
				_logger.LogTrace("{Data}", data);
			}

			public void LogInformation(string data)
			{
				_logger.LogInformation("{Data}", data);
			}

			public void LogMinimal(string data)
			{
				LogVerbose(data);
			}

			public void LogWarning(string data)
			{
				_logger.LogWarning("{Data}", data);
			}

			public void LogError(string data)
			{
				_logger.LogError("{Data}", data);
			}

			public void LogInformationSummary(string data)
			{
				LogInformation(data);
			}

			public void Log(LogLevel level, string data)
			{
				_logger.Log(GetLogLevel(level), "{Data}", data);
			}

			public void Log(ILogMessage message)
			{
				Log(message.Level, message.Message);
			}

			public Task LogAsync(LogLevel level, string data)
			{
				Log(level, data);
				return Task.CompletedTask;
			}

			public Task LogAsync(ILogMessage message)
			{
				Log(message);
				return Task.CompletedTask;
			}

			private static Microsoft.Extensions.Logging.LogLevel GetLogLevel(LogLevel level)
			{
				return level switch
				{
					LogLevel.Debug       => Microsoft.Extensions.Logging.LogLevel.Debug,
					LogLevel.Error       => Microsoft.Extensions.Logging.LogLevel.Error,
					LogLevel.Information => Microsoft.Extensions.Logging.LogLevel.Information,
					LogLevel.Minimal     => Microsoft.Extensions.Logging.LogLevel.Trace,
					LogLevel.Verbose     => Microsoft.Extensions.Logging.LogLevel.Trace,
					LogLevel.Warning     => Microsoft.Extensions.Logging.LogLevel.Warning,
					_                    => Microsoft.Extensions.Logging.LogLevel.None
				};
			}
		}
	}
}