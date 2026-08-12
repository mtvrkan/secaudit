# INTENTIONALLY VULNERABLE — SecAudit test fixture. Not real infrastructure. Do not apply.

# V40 — Security group open to the world (CWE-284): every address may reach the admin port.
resource "aws_security_group_rule" "admin" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# V41 — Public-read storage ACL (CWE-732): anonymous readers can list and fetch every object.
resource "aws_s3_bucket_acl" "reports" {
  bucket = "example-reports"
  acl    = "public-read"
}

# V42 — Over-broad IAM policy (CWE-732): every action on every resource.
resource "aws_iam_policy" "app" {
  name   = "app"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", "Action" = "*", "Resource" = "*" }]
  })
}

# V43 — Storage encryption disabled (CWE-311): data at rest is written in the clear.
resource "aws_db_instance" "primary" {
  identifier        = "primary"
  storage_encrypted = false
  publicly_accessible = true
}

# V44 — Database publicly accessible (CWE-284): the managed database has a public endpoint.
resource "aws_db_instance" "replica" {
  identifier          = "replica"
  publicly_accessible = true
}
