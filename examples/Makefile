examples:
	@echo "building k9 policy examples"
	@set -e
	@echo "compiling k9-cdk library"
	@cd .. && npx projen compile
	@echo "installing example dependencies"
	@npm install
	@echo "running build"
	@npm run build
	@echo "synthesizing CDK"
	@cdk synth
	@cp cdk.out/K9Example.template.json .

