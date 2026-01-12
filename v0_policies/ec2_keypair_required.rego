package terraform.ec2_keypair_required

import input.plan as plan

# METADATA
# title: EC2 Key Pair Required
# description: EC2 instances must specify an SSH key pair
# custom:
#  enforcement_level: advisory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_instance"
	r.change.after.key_name == null

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: EC2 instance has no SSH key pair configured",
			                    [r.address])
	}
}
