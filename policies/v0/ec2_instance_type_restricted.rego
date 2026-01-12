package terraform.ec2_instance_type_restricted

import input.plan as plan

# METADATA
# title: EC2 Instance Type Restricted
# description: EC2 instances must not use t2.nano instance type
# custom:
#  enforcement_level: mandetory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_instance"
	r.change.after.instance_type == "t2.nano"

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: EC2 instance uses restricted instance type",
			                    [r.address])
	}
}
