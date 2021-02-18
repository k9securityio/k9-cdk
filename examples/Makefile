examples:
	@echo "building k9 policy examples"
	@set -e
	@npm install
	@npm run build
	@node example.js
	@cdk synth
	@cp cdk.out/K9Example.template.json .

