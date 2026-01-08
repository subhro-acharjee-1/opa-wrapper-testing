package terraform.ec2_high_risk_configuration

import input.plan as plan

# METADATA
# title: EC2 High Risk Configuration
# description: EC2 instances violating multiple baseline security controls
# custom:
#  enforcement_level: mandetory
rule contains outcome if {
	type_violations := data.terraform.ec2_instance_type_restricted.rule
	iam_violations  := data.terraform.ec2_iam_profile_required.rule
	sg_violations   := data.terraform.ec2_security_group_required.rule

    some item in type_violations
    print(type_violations)

	count(type_violations) > 0 
    count(iam_violations)== 0
    count(sg_violations) == 0 

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws_instance :: EC2 instance violates compute, IAM, and network policies"
	}
}
