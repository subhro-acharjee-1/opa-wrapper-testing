package terraform.public_exposure_risk

import input.plan as plan

# METADATA
# title: Public Exposure Risk
# description: Infrastructure exposes potential public attack surface
# custom:
#  enforcement_level: mandetory

has_violations(v) {
	count(v) > 0
}

rule[outcome] {
	has_violations(data.terraform.ec2_public_ip_unknown.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "infrastructure :: One or more resources expose public access risks"
	}
}

rule[outcome] {
	has_violations(data.terraform.s3_no_public_acl.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "infrastructure :: One or more resources expose public access risks"
	}
}

rule[outcome] {
	has_violations(data.terraform.ec2_security_group_required.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "infrastructure :: One or more resources expose public access risks"
	}
}
