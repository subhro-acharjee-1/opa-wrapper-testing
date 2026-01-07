package terraform.aws_provider_no_static_secret

import input.plan as plan

# METADATA
# title: AWS Provider No Static Secret
# description: AWS provider must not use hardcoded secret keys
# custom:
#  enforcement_level: mandetory
rule contains outcome if {
	plan.configuration.provider_config.aws.expressions.secret_key.constant_value

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws.provider :: Hardcoded AWS secret key detected"
	}
}
