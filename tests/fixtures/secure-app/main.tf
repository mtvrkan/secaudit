# SECURE COUNTERPART — SecAudit negative-control fixture. Not real infrastructure.

# S40 — Ingress restricted (CWE-284 fixed): administration reachable only from the bastion's
# own range, not from the internet.
resource "aws_security_group_rule" "admin" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.16.0/20"]
}

# S41 — Private bucket (CWE-732 fixed): no anonymous access; objects are served through
# time-limited signed URLs instead.
resource "aws_s3_bucket_acl" "reports" {
  bucket = "example-reports"
  acl    = "private"
}

# S42 — Scoped IAM policy (CWE-732 fixed): the two actions the service needs, on its bucket.
resource "aws_iam_policy" "app" {
  name   = "app"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow",
      Action   = ["s3:GetObject", "s3:PutObject"],
      Resource = "arn:aws:s3:::example-reports/*"
    }]
  })
}

# S43 — Encryption at rest enabled (CWE-311 fixed).
resource "aws_db_instance" "primary" {
  identifier          = "primary"
  storage_encrypted   = true
  publicly_accessible = false
}

# S44 — Database kept private (CWE-284 fixed): reachable only inside the VPC.
resource "aws_db_instance" "replica" {
  identifier          = "replica"
  publicly_accessible = false
}
