# Elrond SDK for JavaScript: core wallet components

Core wallet components (generation, signing) for TypeScript (JavaScript). 

## CHANGELOG

[CHANGELOG](CHANGELOG.md)

## Distribution

[npm](https://www.npmjs.com/package/@elrondnetwork/erdjs-walletcore)

## Installation

`erdjs-walletcore` is delivered via [npm](https://www.npmjs.com/package/@elrondnetwork/erdjs-walletcore), therefore it can be installed as follows:

```
npm install @elrondnetwork/erdjs-walletcore
```

## Development

Feel free to skip this section if you are not a contributor.

### Prerequisites

`browserify` is required to compile the browser-friendly versions of `erdjs-walletcore`. It can be installed as follows:

```
npm install --global browserify
```

### Building the library

In order to compile `erdjs-walletcore`, run the following:

```
npm install
npm run compile
npm run compile-browser
npm run compile-browser-min
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
