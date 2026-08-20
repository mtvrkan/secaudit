# SECURE COUNTERPART — SecAudit negative-control fixture. Not real code.
require 'json'

# S33 — Insecure deserialization fixed (CWE-502): JSON produces hashes and scalars only, so
# the payload cannot choose a class to instantiate.
def restore(blob)
  JSON.parse(blob)
end

# S34 — Dynamic execution fixed (CWE-95): rules are looked up in an explicit table rather than
# evaluated. An unknown rule is refused instead of being run.
RULES = {
  'double' => ->(n) { n * 2 },
  'negate' => ->(n) { -n }
}.freeze

def apply_rule(name, value)
  handler = RULES[name]
  raise ArgumentError, 'unknown rule' unless handler

  handler.call(value)
end
