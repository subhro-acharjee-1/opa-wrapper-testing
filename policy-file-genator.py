policies = [
    ("ec2_instance_type_restricted", "data.terraform.ec2_instance_type_restricted.rule", "mandatory"),
    ("ec2_iam_profile_required", "data.terraform.ec2_iam_profile_required.rule", "mandatory"),
    ("ec2_subnet_required", "data.terraform.ec2_subnet_required.rule", "mandatory"),
    ("ec2_security_group_required", "data.terraform.ec2_security_group_required.rule", "mandatory"),
    ("ec2_public_ip_unknown", "data.terraform.ec2_public_ip_unknown.rule", "advisory"),
    ("s3_no_public_acl", "data.terraform.s3_no_public_acl.rule", "mandatory"),
    ("aws_provider_no_static_keys", "data.terraform.aws_provider_no_static_keys.rule", "mandatory"),
    ("aws_provider_no_static_secret", "data.terraform.aws_provider_no_static_secret.rule", "mandatory"),
    ("ec2_keypair_required", "data.terraform.ec2_keypair_required.rule", "advisory"),
    ("ec2_ami_required", "data.terraform.ec2_ami_required.rule", "mandatory"),
    ("ec2_high_risk_configuration", "data.terraform.ec2_high_risk_configuration.rule", "advisory"),
    ("public_exposure_risk", "data.terraform.public_exposure_risk.rule", "mandatory"),
]

for i in range(1, 1001):
    for name, query, level in policies:
        print(f'''policy {name}_{i} {{
query = "{query}"
enforcement_level = "{level}"
}}
''')
