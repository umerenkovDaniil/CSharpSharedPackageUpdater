using System;

namespace CSharpSharedPackageUpdater.Exceptions
{
	public class ManualRequiredException : Exception
	{
		public object? Obj
		{
			get => Data["obj"];
			set => Data["obj"] = value;
		}

		public ManualRequiredException(string message, object? obj = default)
			: base(message)
		{
			Obj = obj;
		}
	}
}