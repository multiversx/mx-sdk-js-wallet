# MultiversX SDK for JavaScript and TypeScript: wallet components

Wallet components (generation, signing) for TypeScript (JavaScript). 

## Distribution

[npm](https://www.npmjs.com/package/@multiversx/sdk-wallet)

## Installation

`sdk-wallet` is delivered via [npm](https://www.npmjs.com/package/@multiversx/sdk-wallet), therefore it can be installed as follows:

```
npm install @multiversx/sdk-wallet
```

## Development

Feel free to skip this section if you are not a contributor.

### Prerequisites

`browserify` is required to compile the browser-friendly versions of `sdk-wallet`. It can be installed as follows:

```
npm install --global browserify
```

### Building the library

In order to compile `sdk-wallet`, run the following:

```
npm install
npm run compile
npm run compile-browser
```

### Running the tests

#### On NodeJS

In order to run the tests **on NodeJS**, do as follows:

```
npm run test
```

#### In the browser

Make sure you have the package `http-server` installed globally.

```
npm install --global http-server
```

In order to run the tests **in the browser**, do as follows:

```
npm run browser-tests
```
