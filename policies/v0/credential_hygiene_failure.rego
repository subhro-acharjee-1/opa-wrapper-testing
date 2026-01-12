package terraform.credential_hygiene_failure

import input.plan as plan

# METADATA
# title: Credential Hygiene Failure
# description: Static credentials combined with missing workload identity
# custom:
#  enforcement_level: mandetory

has_violations(v) {
	count(v) > 0
}

rule[outcome] {
	has_violations(data.terraform.aws_provider_no_static_keys.rule)
	has_violations(data.terraform.aws_provider_no_static_secret.rule)
	has_violations(data.terraform.ec2_iam_profile_required.rule)

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws.credentials :: Static credentials combined with weak EC2 identity"
	}
}
