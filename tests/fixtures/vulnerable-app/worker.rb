# INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real code. Do not deploy.

# V33 — Insecure deserialization (CWE-502): Marshal reconstructs arbitrary Ruby objects, so a
# queue payload decides which classes get instantiated.
def restore(blob)
  Marshal.load(blob)
end

# V34 — Dynamic code execution (CWE-95): a stored expression is evaluated as Ruby.
def apply_rule(rule)
  eval(rule)
end
