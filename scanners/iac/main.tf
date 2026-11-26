provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "logs" {
  bucket = "demo-secops-logs-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "ssh_open" {
  name        = "demo-ssh-open"
  description = "SSH open to the world (demo)"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "ap-south-1a"
  size              = 10
  encrypted         = false
}
