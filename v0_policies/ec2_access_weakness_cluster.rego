package terraform.ec2_access_weakness_cluster

import input.plan as plan

# METADATA
# title: EC2 Access Weakness Cluster
# description: EC2 instances with weak access configuration
# custom:
#  enforcement_level: advisory

has_violations(v) {
	count(v) > 0
}

rule[outcome] {
	has_violations(data.terraform.ec2_keypair_required.rule)
	has_violations(data.terraform.ec2_public_ip_unknown.rule)
	has_violations(data.terraform.ec2_security_group_required.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws_instance :: EC2 access configuration is weak across multiple controls"
	}
}
