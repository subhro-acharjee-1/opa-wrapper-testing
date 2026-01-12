package terraform.ec2_iam_profile_required

import input.plan as plan

# METADATA
# title: EC2 IAM Profile Required
# description: EC2 instances must have an IAM instance profile attached
# custom:
#  enforcement_level: mandetory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_instance"
	r.change.after.iam_instance_profile == null

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: EC2 instance has no IAM instance profile",
			                    [r.address])
	}
}
