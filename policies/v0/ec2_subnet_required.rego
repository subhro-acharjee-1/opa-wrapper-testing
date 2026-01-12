package terraform.ec2_subnet_required

import input.plan as plan

# METADATA
# title: EC2 Subnet Required
# description: EC2 instances must be associated with a subnet
# custom:
#  enforcement_level: mandetory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_instance"
	r.change.after.subnet_id == null

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: EC2 instance is not associated with a subnet",
			                    [r.address])
	}
}
