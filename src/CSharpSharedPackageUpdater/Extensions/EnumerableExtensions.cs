using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CSharpSharedPackageUpdater.Extensions
{
	public static class EnumerableExtensions
	{
		public static Task ForEachIndexedAsync<T>(
			this T[] source,
			Func<int, Task> body,
			int maxDegreeOfParallelism = 10,
			bool throwOnException = true,
			CancellationToken token = default)
		{
			return Enumerable.Range(0, source.Length).ForEachAsync(body, maxDegreeOfParallelism, throwOnException, token);
		}

		public static Task ForEachAsync<T>(
            this IEnumerable<T> source,
            Func<T, Task> body,
            int maxDegreeOfParallelism = 10,
            bool throwOnException = true,
            CancellationToken token = default)
        {
            var asArray = source.ToArray();
            if (!asArray.Any()) return Task.CompletedTask;

            if (maxDegreeOfParallelism <= 0 && maxDegreeOfParallelism != -1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxDegreeOfParallelism));
            }

            if (asArray.Length == 1) return body.Invoke(asArray[0]);
            var maxDegree = asArray.Length < maxDegreeOfParallelism ? asArray.Length : maxDegreeOfParallelism;

            var tasks = Partitioner.Create(asArray)
                .GetPartitions(maxDegree)
                .Select(partition => ForEachBasic(partition, body, throwOnException, token));

            return Task.WhenAll(tasks);
        }

		private static Task ForEachBasic<T>(
            IEnumerator<T> partition,
            Func<T, Task> body,
            bool throwOnException = true,
            CancellationToken token = default)
        {
            return Task.Run(
	            async () =>
	            {
	                if (token.IsCancellationRequested) return;

	                using (partition)
	                {
	                    while (partition.MoveNext())
	                    {
							if (token.IsCancellationRequested) return;

							await body(partition.Current).ContinueWith(
								t =>
		                        {
		                            if (t.Status != TaskStatus.Faulted) return;
		                            if (throwOnException && t.Exception != null) throw t.Exception;
		                        },
								token);
	                    }
	                }
	            },
	            token);
        }
	}
}