

class RSA{
    static FITST_PRIMES_LIST  = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
        .map(n=>BigInt(n));

    static PADDING_K0 = 32;
    static PADDING_K1 = 8;
    static PADDING_N = 64;
    static HASH_FUNCTION = SHA256.instance.encode.bind(SHA256.instance);
    static HASH_FUNCTION_G = RSA.HASH_FUNCTION;
    static HASH_FUNCTION_H = RSA.HASH_FUNCTION;

    _privateKey;
    _publicKey;
    
    get publicKey(){
        return this._serializeKey(this._publicKey);
    }
    get privateKey(){
        var [d, n, p, q, dmp1, dmq1, coeff] = this._privateKey;
        return this._serializeKey([p, q, d]);
    }
    set publicKey(pubkey){
        this._publicKey = this._deserializeKey(pubkey);
    }
    set privateKey(prikey){
        var [p, q, d] = this._deserializeKey(prikey);
        var [dmp1, dmq1, coeff] = this._factorPrivate(p, q, d);
        var n = p*q;
        this._privateKey = [d, n, p, q, dmp1, dmq1, coeff];
    }
    
    generateKeyPair(bits=2048n){ // 2048 bits is to slow
        bits = BigInt(bits);
        var [p, q] = this._getTwoPrimes(bits);
        var n = p*q;
        var lambda_n = RSA.lcm(p - 1n, q - 1n);
        var e = this._getE(lambda_n, p, q);
        var [k, d, r] = this._extendedEuclidean(lambda_n, e);

        if(r !== 1n) return generateKeyPair(bits); //throw 'extendedEuclidean fall.';
        if(d < 0n) {
            d = d % lambda_n;
            d += lambda_n;
        }
        if(!this._isKeyPairSafe(p, q, n, e, d, bits)) return generateKeyPair(bits); //throw 'the keypair are not safe.';
        var [dmp1, dmq1, coeff] = this._factorPrivate(p, q, d);
        this._publicKey = [e, n];
        this._privateKey = [d, n, p, q, dmp1, dmq1, coeff];
        
        return this;
    }

    encrypt(M){
        var [e, n] = this._publicKey;
        return this._encrypt(M, false, [e, n]);
    }
    decrypt(C){
        return this._decrypt(C, true, this._privateKey);
    }

    sign(M){
        M = RSA.HASH_FUNCTION(M);
        return this._encrypt(M, true, this._privateKey);
    }
    verify(S, M){
        var [e, n] = this._publicKey;
        var C = this._decrypt(S, false, [e, n]);
        M = RSA.HASH_FUNCTION(M);
        for(var i=0; i<M.length; i++){
            if(M[i] !== C[i]) return false;
        }
        return true;
    }

    checkKeyPairCorrectness(iter=3){
        var data, encrypted, decrypted, signData;
        for(var i=0; i<iter; i++){
            data = this._bint2arr(RSA.randint(1n<<511n, 1n<<512n));
            signData = this._bint2arr(RSA.randint(1n<<511n, 1n<<512n));
            encrypted = this.encrypt(data);
            decrypted = this.decrypt(encrypted);
            for(var i=0; i<data.length; i++){
                if(data[i] !== decrypted[i]) return false;
            }
            if(!(this.verify(this.sign(data), data) && !this.verify(this.sign(signData), data))) return false;
        }
        return true;
    }


    _encrypt(M, privateMod = false, key){
        var C;
        var n = key[1];
        M = this._paddingSplit(M);
        M = this._splitByN(M, n);

        var _len, _arr;
        
        _len = M.length, C = Array(_len);
        var max = 0;
        for(var i=0; i<_len; i++){
            var m, c;
            m = M[i];
            m = this._arr2bint(m);
            c = privateMod ?　this._doPrivateModExp(m, key[2], key[3], key[4], key[5], key[6]) :　RSA.modExp(m, key[0], key[1]);
            c = this._bint2arr(c);
            
            max = max > c.length ? max : c.length;
            C[i] = c;
        }
        //Uniform length
        _len = C.length, _arr = Array(_len);
        for(var i=0; i<_len; i++){
            var r = max - C[i].length;
            _arr[i] = this._paddingZeros(C[i], r);
        }
        C = _arr;
        
        C = this._flatArray(C);
        C = this._concatArray([max], C); //add chunk size
        return C;
    }
    _decrypt(C, privateMod = false, key){
        var M;
        var n = key[1];
        var chunkSize = BigInt(C[0]);
        var _len, _arr;
        //remove chunckSize in C
        _len = C.length , _arr = new Uint8Array(_len-1);
        for(var i=1; i<_len; i++){
            _arr[i-1] = C[i];
        }
        C = _arr;
        
        C = this._splitByN(C, n, chunkSize);
        
        _len = C.length , M = Array(_len);
        for(var i=0; i<_len; i++){
            var m, c;
            c = C[i];
            c = this._arr2bint(c);
            m = privateMod ?　this._doPrivateModExp(c, key[2], key[3], key[4], key[5], key[6]) :　RSA.modExp(c, key[0], key[1]);
            m = this._bint2arr(m);
            M[i] = m;
        }
        
        M = this._flatArray(M);
        M = this._unpaddingSplit(M);
        return M;
    }

    _factorPrivate(p, q, d){
        var [k, coeff, r] = this._extendedEuclidean(p, q);
        var [dmp1, dmq1] = [d % (p-1n), d % (q-1n)];
        return [dmp1, dmq1, coeff];
    }
    _doPrivateModExp(x, p, q, dmp1, dmq1, coeff) {
        // TODO: re-calculate any missing CRT params
        let xp = RSA.modExp(x % p, dmp1, p);
        const xq = RSA.modExp(x % q, dmq1, q);

        while (xp < xq) {
            xp += p;
        }
        return (((xp - xq) * coeff) % p) * q + xq;
    }

    
    _splitByN(arr, n, chunkSize=null){ // 0 <= m < n
        var x = BigInt(n.toString(2).length - 1);
        if(n % (1n << x) === 0n) x++;
        if(chunkSize===null) chunkSize = x / 8n;//must less than n, hence can not + 1;
        var arrLength = BigInt(arr.length);
        var len = arrLength / chunkSize;
        if(arrLength % chunkSize !== 0n) len++;
        var result = Array(Number(len));
        for(var i=0n; i<len; i++){
            result[i] = arr.slice(Number(i*chunkSize), Number((i + 1n)*chunkSize));
        }
        return result;
    }

    _serializeKey(k){// k is array of bigint
        const chunkSize = RSA.PADDING_N;
        
        var nKeys = k.length;
        var resLenArr = new Uint8Array(nKeys);
        var totalLen = 0;
        var _arr = Array(nKeys);
        for(var i=0; i<nKeys; i++){
            var _tmp = k[i];
            _tmp = this._bint2arr(_tmp);
            _tmp = this._paddingSplit(_tmp);
            _arr[i] = _tmp;
            totalLen += _tmp.length;
            resLenArr[i] = Math.floor(_tmp.length / chunkSize);
        }

        totalLen = totalLen + nKeys;
        var resArr = new Uint8Array(totalLen); //[e.length, e.arr, n.arr]

        var offset = 0;
        resArr[offset++] = nKeys;// set number of components
        for(var j=0; j<nKeys-1; j++){// set length of key components
            resArr[offset++] = resLenArr[j];
        }
        for(var j=0; j<nKeys; j++){// set values to resArr
            var _tmp = _arr[j];
            for(var k = 0; k < _tmp.length; k++){
                resArr[offset++] = _tmp[k];
            }
        }
        
        return resArr;
    }
    _deserializeKey(k){
        const chunkSize = RSA.PADDING_N;
        
        var offset = 0;
        var nKeys = k[offset++];
        var lenArr = new Uint8Array(nKeys);
        var totalLen;
        var _tmp = 0;
        for(var i=0; i< nKeys-1; i++){
            lenArr[i] = k[offset++];
            _tmp += lenArr[i];
        }
        totalLen = k.length - offset;
        lenArr[nKeys-1] = totalLen - _tmp;
        var resArr = Array(nKeys);
        for(var i=0; i< nKeys; i++){
            var _k;
            var size = lenArr[i] * chunkSize;
            
            _k = k.slice(offset, offset + size);
            _k = this._unpaddingSplit(_k);
            _k = this._arr2bint(_k);
            resArr[i] = _k;

            offset += size;
        }
        return resArr;
    }

    _paddingSplit(message){//split array to 24 length, because some array may to long.
        const n = RSA.PADDING_N, k0 = RSA.PADDING_K0, k1 = RSA.PADDING_K1;
        const inc = n - k0 - k1;

        var iter = Math.floor(message.length / inc);
        if(message.length % inc !== 0) iter++;
        var result = Array(iter);
        for(var i=0,offset=0; i<iter; i++, offset += inc){
            var m = message.slice(offset, offset+inc);
            if(m.length <= inc){
                m = this._paddingZeros(m, inc - m.length);
            }
            result[i] = this._padding(m);
        }
        return this._flatArray(result);
    }
    _unpaddingSplit(message){//
        const chunkSize = RSA.PADDING_N;
        if(message.length % chunkSize !== 0) message = this._paddingZeros(message, chunkSize - (message.length % chunkSize) ); //padding zeros
        
        var iter = Math.floor(message.length / chunkSize);
        
        var result = Array(iter);
        for(var i=0,offset=0; i<iter; i++, offset += chunkSize){
            var R = message.slice(offset, offset+chunkSize);
            result[i] = this._unpadding(R);
        }
        return this._flatArray(result);
    }


    _padding(m){ //required length: n-k0-k1 = 24, output length: n = 64
        const n = RSA.PADDING_N, k0 = RSA.PADDING_K0, k1 = RSA.PADDING_K1;
        const [G, H] = [RSA.HASH_FUNCTION_G, RSA.HASH_FUNCTION_H];

        m = this._paddingZeros(m, k1); // padding k1 zeros
        
        var r = crypto.getRandomValues(new Uint8Array(k0));
        var X = this._xorArray(m,  G(r)); //assert X.length === n - k0;
        var Y = this._xorArray(r, H(X));

        return this._concatArray(X, Y);
    }
    _unpadding(R){//output length: 24
        const n = RSA.PADDING_N, k0 = RSA.PADDING_K0, k1 = RSA.PADDING_K1;
        const [G, H] = [RSA.HASH_FUNCTION_G, RSA.HASH_FUNCTION_H];
        
        var [X, Y] = [R.slice(0, n - k0), R.slice(n - k0, n)];
        var r = this._xorArray(Y, H(X));
        var mZeros = this._xorArray(X, G(r));
        return mZeros.slice(0, n - k0 - k1);
    }
    _xorArray(a, b){
        var result = new Uint8Array(a.length);
        for(var i=0; i<a.length; i++){
            result[i] = a[i] ^ b[i];
        }
        return result;
    }
    _paddingZeros(arr, numOfZeros){
        numOfZeros = Number(numOfZeros);
        var len = arr.length + numOfZeros;
        var result = new Uint8Array(len);
        for(var i=0; i<arr.length; i++) result[i] = arr[i];
        for(var i=arr.length; i<len; i++) result[i] = 0;
        return result;
    }
    _flatArray(arr){ // two dim array required
        var len = 0;
        for(var i=0; i<arr.length; i++){
            len += arr[i].length;
        }
        var result = new Uint8Array(len);
        var offset = 0;
        for(var i=0; i<arr.length; i++){
            for(var j=0; j<arr[i].length; j++)
                result[offset++] = arr[i][j];
        }
        return result;
    }
    _concatArray(A, B){
        var al = A.length, len = al + B.length;
        var result = new Uint8Array(len);
        for(var i=0; i<al; i++) result[i] = A[i];
        for(var i=0, j=al; j<len; i++, j++) result[j] = B[i];
        return result;
    }

    _arr2bint(arr){
        var len = arr.length;
        var bint = 0n;
        for(var i=0n;i<len;i++){
            bint += BigInt(arr[i]) << (8n*i)
        }
        return bint;
    }
    _bint2arr(bint){
        var ln2 = bint.toString(2).length;
        var len = ln2 / 8;
        if(ln2 % 8 !== 0) len++;
        var buffer = new Uint8Array(len);
        for(var i=0; i<len; i++) {
            buffer[i] = Number(bint%256n);
            bint >>= 8n;
        }
        return buffer;
    }

    _isKeyPairSafe(p, q, n, e, d, bits){
        if(p < 2n*q && p > q && d < 2n**(bits/4n) / 3n) return false;
        return true;
    }

    _getTwoPrimes(bits){
        /** p - q should larger than 2n^{1/4}*/
        var pBits = bits/2n;
        var range = [2n**(pBits-1n)+1n, 2n**pBits - 1n];
        var step = range[1] - range[0];
        var dist = 1n<<(bits/4n + 2n);
        return [this._generatePrimeNumberByProbability(range[1] + dist, range[1] + dist + step), this._generatePrimeNumberByProbability(range[0], range[1])];
    }

    /** modify from https://github.com/travist/jsencrypt*/
    _getLowLevelPrime(n0, n1){
        const LOW_PRIME_LIST = RSA.FITST_PRIMES_LIST
        const LOW_PRIME_LENGTH = LOW_PRIME_LIST.length;
        const BIG_LOW_PRIME = RSA.FITST_PRIMES_LIST[LOW_PRIME_LENGTH - 1];
        const lplim = (1n << 26n) / BIG_LOW_PRIME + 1n;

        while(true){
            // Obtain a random number
            var x = RSA.randint(n0, n1);
            if((x & 1n) === 0n) x = x + 1n;

            if (x < (1n<<28n) && x <= BIG_LOW_PRIME) { // check if x is prime that in list "LOW_PRIME_LIST"
                for (var i = 1; i < LOW_PRIME_LENGTH; i++) {// not including 2
                    if (x === LOW_PRIME_LIST[i]) {
                        return x;
                    }
                }
                continue;
            }
            
            var i = 1;
            var _notPrime = false;
            while (i < LOW_PRIME_LENGTH) {
                let m = LOW_PRIME_LIST[i];
                let j = i + 1;
                while (j < LOW_PRIME_LENGTH && m < lplim) {
                    m *= LOW_PRIME_LIST[j++];
                }
                m = x % m;
                while (i < j) {
                    if (m % LOW_PRIME_LIST[i++] === 0n) {
                        _notPrime = true;
                        break;
                    }
                }
                if(_notPrime) break;
            }
            if(_notPrime) continue;
            return x;
        }
    }
    /** modify from https://github.com/travist/jsencrypt*/
    _MillerRabinPrimalityTest(n, t = 10n) {
        const LOW_PRIME_LIST = RSA.FITST_PRIMES_LIST
        const LOW_PRIME_LENGTH = LOW_PRIME_LIST.length;
        const n1 = n - 1n;
    
        var k = 0n;
        while(true){
            if((n1 & (1n << k)) !== 0n) break;
            k++;
        }
    
        if (k <= 0n) {
            return false;
        }
        const r = n1 >> k;
        t = (t + 1n) >> 1n;
        if (t > LOW_PRIME_LENGTH) {
            t = LOW_PRIME_LENGTH;
        }
        var count = Number(RSA.randint(0n, BigInt(LOW_PRIME_LENGTH)));
        for (let i = 0n; i < t; ++i, count=(count+1)%LOW_PRIME_LENGTH) {
            // Pick bases at random, instead of starting at 2
            var a = LOW_PRIME_LIST[count];
            let y = RSA.modExp(a, r, n);
            if (y !== 1n && y !== n1) {
                let j = 1;
                while (j++ < k && y !== n1) {
                    y = y*y % n;
                    if (y === 1n) {
                        return false;
                    }
                }
                if (y !== n1) {
                    return false;
                }
            }
        }
        return true;
    }
    
    _extendedEuclidean(a, b){
        var [old_s, s] = [1n, 0n];
        var [old_t, t] = [0n, 1n];
        var [old_r, r] = [a, b];
        if (b === 0n) return [1n, 0n, a];
        else{
            while(r !== 0n){
                var q = old_r / r;
                [old_r, r] = [r, old_r-q*r];
                [old_s, s] = [s, old_s-q*s];
                [old_t, t] = [t, old_t-q*t];
            }
        }
        return [old_s, old_t, old_r];
    }
    _generatePrimeNumberByProbability(n0, n1, maxIter=1632){
        for(var i=0; i<maxIter; i++){
            var prime_candidate = this._getLowLevelPrime(n0, n1);
            if (!this._MillerRabinPrimalityTest(prime_candidate))
                continue;
            else
                return prime_candidate;
        }
        throw 'can not find prime number';
    }

    _getE(lambda_n, p, q){
        //method 1: use 2^16 + 1, ...
        var e_list1_pre = [65537n, 257n, 17n];
        for(var i=0; i<e_list1_pre.length; i++){
            var e = e_list1_pre[i];
            if(1n < e && e < lambda_n && lambda_n % e !== 0/*since e is prime*/) return e;
        }
        
        //method 2: use prime number.
        var a = RSA.gcd(p - 1n, q - 1n);
        var b = (p-1n / a);
        var c = (q-1n / a);
        var maxVal = a > b ? a : b;
        maxVal = maxVal > c ? maxVal : c;
        for(var i=0; i<100; i++){
            var prime = this._getLowLevelPrime(65536n, maxVal);
            if(this._MillerRabinPrimalityTest(prime) && prime < lambda_n && lambda_n % e !== 0/*since e is prime*/){
                return prime;
            }
        }
        //method 3:　force.
        var e = lambda_n - 1n;
        while (e > 65536n){
            if (RSA.gcd(e, lambda_n) === 1n){
                return e;
            }
            e--;
        }
        
        throw 'can not find e.';
    }
    
    static randint(start, end){
        var range = end - start;
        var p = Math.ceil(Math.log2(Number(range)) / 8);
        var randArr = crypto.getRandomValues(new Uint8Array(p));
        var bint = 0n;
        var len = BigInt(p);
        
        for(var i=0n;i<len;i++){
            bint += BigInt(randArr[i]) << (8n*i);
        }
        bint = range*bint / (1n<<(len<<3n)) + start;
        return bint;
    }
    static gcd(a, b){//Greatest Common Divisor Generator (Euclidean Algorithm)
        while (b !== 0n){
            [a, b] = [b, a % b];
        }
        return a;
    }
    static lcm(a, b){
        return a * b / RSA.gcd(a, b);
    }
    static log(n){
        var _ln = BigInt(n.toString(2).length - 1);
        return (_ln << 16n) / 94548n;
    }
    static modExp(x, e, m){
        var [X, E, Y] = [x, e, 1n];
        while (E > 0n){
            if (E % 2n === 0n){
                X = (X * X) % m;
                E = E / 2n;
            }else{
                Y = (X * Y) % m;
                E = E - 1n;
            }
        }
        return Y;
    }
}
