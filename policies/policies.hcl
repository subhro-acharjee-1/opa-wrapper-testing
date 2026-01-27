policy ec2_instance_type_restricted_1 {
query = "data.terraform.ec2_instance_type_restricted.rule"
enforcement_level = "mandatory"
}

policy ec2_iam_profile_required_1 {
query = "data.terraform.ec2_iam_profile_required.rule"
enforcement_level = "mandatory"
}

policy ec2_subnet_required_1 {
query = "data.terraform.ec2_subnet_required.rule"
enforcement_level = "mandatory"
}

policy ec2_security_group_required_1 {
query = "data.terraform.ec2_security_group_required.rule"
enforcement_level = "mandatory"
}

policy ec2_public_ip_unknown_1 {
query = "data.terraform.ec2_public_ip_unknown.rule"
enforcement_level = "mandatory"
}

policy s3_no_public_acl_1 {
query = "data.terraform.s3_no_public_acl.rule"
enforcement_level = "mandatory"
}

policy aws_provider_no_static_keys_1 {
query = "data.terraform.aws_provider_no_static_keys.rule"
enforcement_level = "mandatory"
}

policy aws_provider_no_static_secret_1 {
query = "data.terraform.aws_provider_no_static_secret.rule"
enforcement_level = "mandatory"
}

policy ec2_keypair_required_1 {
query = "data.terraform.ec2_keypair_required.rule"
enforcement_level = "advisory"
}

policy ec2_ami_required_1 {
query = "data.terraform.ec2_ami_required.rule"
enforcement_level = "mandatory"
}

policy ec2_high_risk_configuration_1 {
query = "data.terraform.ec2_high_risk_configuration.rule"
enforcement_level = "advisory"
}

policy public_exposure_risk_1 {
query = "data.terraform.public_exposure_risk.rule"
enforcement_level = "mandatory"
}
