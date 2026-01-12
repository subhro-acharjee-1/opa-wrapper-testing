package terraform.s3_no_public_acl

import input.plan as plan

# METADATA
# title: S3 No Public ACL
# description: S3 buckets must not use public ACLs
# custom:
#  enforcement_level: mandetory

rule[outcome] {
	r := plan.resource_changes[_]
	r.type == "aws_s3_bucket"
	r.change.after.acl == "public"

	meta := rego.metadata.chain()

	outcome := {
		"policy_name": rego.metadata.rule().title,
		"description": rego.metadata.rule().description,
		"enforcement_level": rego.metadata.rule().custom.enforcement_level,
		"output": sprintf("%-40s :: S3 bucket is publicly accessible via ACL",
			                    [r.address])
	}
}
