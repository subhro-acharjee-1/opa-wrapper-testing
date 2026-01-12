package terraform.aws_provider_no_static_keys

import input.plan as plan

# METADATA
# title: AWS Provider No Static Keys
# description: AWS provider must not use hardcoded access keys
# custom:
#  enforcement_level: mandetory

rule[outcome] {
    configuration = plan.configuration[_]
	configuration.provider_config.aws.expressions.access_key.constant_value

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": "aws.provider :: Hardcoded AWS access key detected"
	}
}
