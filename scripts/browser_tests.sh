npm install --no-save babelify@10.0.0 browserify@17.0.0 esmify@2.1.1 http-server@14.1.1 || exit 1
rm -rf out-tests
tsc -p tsconfig.tests.json || exit 1
cp -r src/testdata out-tests || exit 1
browserify $(find out-tests -type f -name '*.js') --require buffer/:buffer -o out-tests/browser-tests.js --standalone tests -p esmify || exit 1
http-server --port=9876 -o browser-tests/index.html || exit 1
