# This package was integrated into [sdk-core](https://www.npmjs.com/package/@multiversx/sdk-core) and will soon be deprecated
To utilize the functionality from the unified @multiversx/sdk-core library, please update the existing import statements within your project.

For example:
``` 
import { UserSigner } from "@multiversx/sdk-wallet";
```
should be changed to:
```
import { UserSigner } from "@multiversx/sdk-core";

```
