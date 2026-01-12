package terraform.unsafe_default_infrastructure

import input.plan as plan

# METADATA
# title: Unsafe Default Infrastructure
# description: Resources relying on insecure or weak defaults
# custom:
#  enforcement_level: mandetory

has_violations(v) {
	count(v) > 0
}

rule[outcome] {
	has_violations(data.terraform.ec2_instance_type_restricted.rule)
	has_violations(data.terraform.ec2_ami_required.rule)
	has_violations(data.terraform.s3_no_public_acl.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "infrastructure :: Multiple resources rely on unsafe defaults"
	}
}
