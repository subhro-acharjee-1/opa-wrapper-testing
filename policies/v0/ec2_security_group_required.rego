package terraform.ec2_security_group_required

import input.plan as plan

# METADATA
# title: EC2 Security Group Required
# description: EC2 instances must use VPC security groups
# custom:
#  enforcement_level: mandetory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_instance"
	count(r.change.after.vpc_security_group_ids) == 0

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: EC2 instance has no security groups attached",
			                    [r.address])
	}
}
