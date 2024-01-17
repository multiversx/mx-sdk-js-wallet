npm install --no-save babelify@10.0.0 browserify@17.0.0 esmify@2.1.1 || exit 1
tsc -p tsconfig.json || exit 1
browserify out/index.js -o out-browser/sdk-wallet.js --standalone multiversxSdkWallet -p esmify || exit 1
