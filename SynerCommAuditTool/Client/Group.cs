using System;
using System.Collections.Generic;

namespace ActiveDirectoryDumper.Client
{
    public class Group
    {
        public String Cn { get; private set; }
        public String Description { get; private set; }
        public String GroupType { get; private set; }
        public int MemberCount { get; private set; }
        public List<String> Members { get; private set; }

        public Group(String cn, String description, String groupType, int memberCount, List<String> members)
        {
            this.Cn = cn;
            this.Description = description;
            this.GroupType = groupType;
            this.MemberCount = memberCount;
            this.Members = members;
        }
    }
}
