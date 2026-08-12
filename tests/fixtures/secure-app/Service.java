// SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
package com.example;

import java.io.*;
import java.sql.*;
import java.util.regex.Pattern;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Service {

    // S27 — Insecure deserialization fixed (CWE-502): a data format that describes values, not
    // classes, and a declared target type. Nothing in the payload can name what to construct.
    public Config load(InputStream in) throws Exception {
        return new ObjectMapper().readValue(in, Config.class);
    }

    // S28 — Command execution fixed (CWE-78): an argument array through ProcessBuilder, so
    // there is no shell string to break out of, and the name is constrained first.
    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");

    public Process convert(String filename) throws Exception {
        if (!NAME.matcher(filename).matches()) {
            throw new IllegalArgumentException("invalid filename");
        }
        return new ProcessBuilder("convert", filename, "/tmp/out.png").start();
    }

    // S29 — SQL injection fixed (CWE-89): PreparedStatement with a bind parameter.
    public ResultSet find(Connection c, String email) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE email = ?");
        ps.setString(1, email);
        return ps.executeQuery();
    }

    public static class Config { public String name; }
}
