policy ec2_instance_type_restricted {
query = "data.terraform.ec2_instance_type_restricted.rule"
enforcement_level = "mandatory"
}

policy ec2_iam_profile_required {
query = "data.terraform.ec2_iam_profile_required.rule"
enforcement_level = "mandatory"
}

policy ec2_subnet_required {
query = "data.terraform.ec2_subnet_required.rule"
enforcement_level = "mandatory"
}

policy ec2_security_group_required {
query = "data.terraform.ec2_security_group_required.rule"
enforcement_level = "mandatory"
}

policy ec2_public_ip_unknown {
query = "data.terraform.ec2_public_ip_unknown.rule"
enforcement_level = "advisory"
}

policy s3_no_public_acl {
query = "data.terraform.s3_no_public_acl.rule"
enforcement_level = "mandatory"
}

policy aws_provider_no_static_keys {
query = "data.terraform.aws_provider_no_static_keys.rule"
enforcement_level = "mandatory"
}

policy aws_provider_no_static_secret {
query = "data.terraform.aws_provider_no_static_secret.rule"
enforcement_level = "mandatory"
}

policy ec2_keypair_required {
query = "data.terraform.ec2_keypair_required.rule"
enforcement_level = "advisory"
}

policy ec2_ami_required {
query = "data.terraform.ec2_ami_required.rule"
enforcement_level = "mandatory"
}

policy ec2_high_risk_configuration {
    query = "data.terraform.ec2_high_risk_configuration.rule"
    enforcement_level="advisory"
}

policy public_exposure_risk {
    query = "data.terraform.public_exposure_risk.rule"
    enforcement_level="mandatory"
}
