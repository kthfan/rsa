# rsa
## Javascript Usage:
### Generate key pair:
```javascript
var rsa = new RSA();
rsa.generateKeyPair(2024); // bits length is 2024.
```
### Encrypt and decrypt:
```javascript
var data = new Uint8Array([1,2,3,4,5,6,7,8,9,0,0,0]);
var encrypted = rsa.encrypt(data);
var decrypted = rsa.decrypt(encrypted);
```
### Get and set key pair:
```javascript
//get
var pubkey = rsa.publicKey;
var prikey = rsa.privateKey;
//set
rsa.publicKey = pubkey;
rsa.privateKey = prikey;
```
### Check if key pair is correct:
```javascript
rsa.generateKeyPair(2024, true); // Check while generating.
console.log(rsa.checkKeyPairCorrectness()); // Check.
```
