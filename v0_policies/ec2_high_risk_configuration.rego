package terraform.ec2_high_risk_configuration

import input.plan as plan

# METADATA
# title: EC2 High Risk Configuration
# description: EC2 instances violating multiple baseline security controls
# custom:
#  enforcement_level: mandetory

has_violations(v) {
	count(v) > 0
}

rule[outcome] {
	has_violations(data.terraform.ec2_instance_type_restricted.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws_instance :: EC2 instance violates one or more high-risk controls"
	}
}

rule[outcome] {
	has_violations(data.terraform.ec2_iam_profile_required.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws_instance :: EC2 instance violates one or more high-risk controls"
	}
}

rule[outcome] {
	has_violations(data.terraform.ec2_security_group_required.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws_instance :: EC2 instance violates one or more high-risk controls"
	}
}
