.PHONY: clean deps build unit-test lint converge verify destroy circleci-build

IMAGE_NAME := TBD
IMAGE_TAG := TBD

FQ_IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)

AWS_AUTH_VARS :=

ifdef AWS_PROFILE
	AWS_AUTH_VARS += $(AWS_AUTH_VARS) -e AWS_PROFILE=$(AWS_PROFILE)
endif

ifdef AWS_ACCESS_KEY_ID
	AWS_AUTH_VARS += $(AWS_AUTH_VARS) -e AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID)
endif

ifdef AWS_SECRET_ACCESS_KEY
	AWS_AUTH_VARS += $(AWS_AUTH_VARS) -e AWS_SECRET_ACCESS_KEY=$(AWS_SECRET_ACCESS_KEY)
endif

ifdef AWS_SESSION_TOKEN
	AWS_AUTH_VARS += $(AWS_AUTH_VARS) -e AWS_SESSION_TOKEN=$(AWS_SESSION_TOKEN)
endif

AWS_OPTS := $(AWS_AUTH_VARS) -e AWS_REGION=$(AWS_REGION)

define execute
	if [ -z "$(CI)" ]; then \
		docker run --rm -it \
			$(AWS_OPTS) \
			-e USER=root \
			-v $(shell pwd):/module \
			-v $(HOME)/.aws:/root/.aws:ro \
			-v $(HOME)/.netrc:/root/.netrc:ro \
			$(FQ_IMAGE) \
			$(1); \
	else \
		echo $(1); \
		$(1); \
	fi;
endef

clean:
	rm -f bin/*.js bin/*.d.ts lib/*.js lib/*.d.ts && rm -rf cdk.out/* node_modules

shell:
	@$(call execute,sh,)

deps:
	@set -e
	@if test -z $(CI); then \
		docker pull $(FQ_IMAGE); \
	fi;

init:
	@echo "installing package dependencies - k9-cdk v2"
	@set -e
	@npm install

build:
	@echo "building k9 policy library - k9-cdk v2"
	@set -e
	@npx projen build

converge:
	@echo "converging integration test stack - k9-cdk v2"
	@set -e
	@cdk synth; \
	cdk deploy --require-approval never --force

destroy:
	@echo "destroying integration test stack - k9-cdk v2"
	@set -e
	@cdk destroy --force;

quick: build

all: init build converge
