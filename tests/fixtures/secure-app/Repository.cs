// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
using System.Data.SqlClient;
using System.IO;
using System.Text.Json;

namespace Example
{
    public class Repository
    {
        // S35 — Insecure deserialization fixed (CWE-502): a data serializer with a declared
        // target type. The payload carries values, never type names.
        public Config Load(Stream s)
        {
            return JsonSerializer.Deserialize<Config>(s);
        }

        // S36 — SQL injection fixed (CWE-89): a placeholder plus a bound parameter.
        public SqlCommand Find(string email)
        {
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Email = @email");
            cmd.Parameters.AddWithValue("@email", email);
            return cmd;
        }
    }

    public class Config { public string Name { get; set; } }
}
