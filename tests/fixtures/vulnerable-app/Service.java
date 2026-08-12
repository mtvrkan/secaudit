// INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.
package com.example;

import java.io.*;
import java.sql.*;

public class Service {

    // V27 — Insecure deserialization (CWE-502): a serialized object graph from the network is
    // reconstructed, which runs code in the classes it names.
    public Object load(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    // V28 — OS command execution (CWE-78): a request value reaches the process runtime.
    public Process convert(String filename) throws Exception {
        return Runtime.getRuntime().exec("convert " + filename + " /tmp/out.png");
    }

    // V29 — SQL injection (CWE-89): concatenated statement on a mutable Statement.
    public ResultSet find(Connection c, String email) throws Exception {
        Statement st = c.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE email = '" + email + "'");
    }
}
