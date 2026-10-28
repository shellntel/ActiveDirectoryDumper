using System;

namespace ActiveDirectoryDumper.Client
{
    /// <summary>One entry of a container's gPLink attribute.</summary>
    public class GpoLink
    {
        /// <summary>Distinguished name of the domain, OU or site that links the GPO.</summary>
        public string Container { get; set; } = String.Empty;

        /// <summary>1 is the highest precedence at that container, as shown in GPMC.</summary>
        public int LinkOrder { get; set; }

        public bool Enabled { get; set; }
        public bool Enforced { get; set; }
    }
}
