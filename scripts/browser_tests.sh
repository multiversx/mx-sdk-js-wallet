rm -rf out-tests
npx tsc -p tsconfig.tests.json
cp -r src/testdata out-tests
npx browserify $(find out-tests -type f -name '*.js') --require buffer/:buffer -o out-tests/browser-tests.js --standalone tests -p esmify	
http-server --port=9876 -o browser-tests/index.html
