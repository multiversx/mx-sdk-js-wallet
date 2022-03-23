.PHONY: clean browser-tests

browser-tests: out-tests
	npx browserify $(shell find out-tests -type f -name '*.js' ! -name '*.net.spec.*') --require buffer/:buffer -o out-browser-tests/erdjs-tests-unit.js --standalone erdjs-tests -p esmify	

out-tests:
	npx tsc -p tsconfig.tests.json

clean:
	rm -rf out-tests
	rm -rf out-browser-tests
