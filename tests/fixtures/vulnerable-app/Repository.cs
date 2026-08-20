// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
using System.Data.SqlClient;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Example
{
    public class Repository
    {
        // V35 — Insecure deserialization (CWE-502): BinaryFormatter reconstructs a typed object
        // graph from untrusted bytes and is unfixable by configuration.
        public object Load(Stream s)
        {
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(s);
        }

        // V36 — SQL injection (CWE-89): the parameter is concatenated into the command text.
        public SqlCommand Find(string email)
        {
            return new SqlCommand("SELECT * FROM Users WHERE Email = '" + email + "'");
        }
    }
}
