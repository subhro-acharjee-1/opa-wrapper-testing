package terraform.always_fail

import input.plan as plan

# METADATA
# title: EC2 Public IP Assignment Unknown
# description: EC2 public IP assignment must be explicitly reviewed
# custom:
#  enforcement_level: advisory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_instance"
	r.change.after_unknown.associate_public_ip_address == true

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: EC2 public IP assignment is unknown at plan time",
			                    [r.address])
	}
}
