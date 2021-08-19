

class RSA{
    static FITST_PRIMES_LIST  = [
        /*2,*/ 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67, 
        71, 73, 79, 83, 89, 97, 101, 103, 
        107, 109, 113, 127, 131, 137, 139, 
        149, 151, 157, 163, 167, 173, 179,      
        181, 191, 193, 197, 199, 211, 223,
    ].map(n=>BigInt(n));

    static PADDING_K0 = 32;
    static PADDING_K1 = 8;
    static PADDING_N = 64;
    static SHA256 = SHA256;

    _privateKey;
    _publicKey;
    
    get publicKey(){
        return this._serializeKeyPair(this._publicKey);
    }
    get privateKey(){
        return this._serializeKeyPair(this._privateKey);
    }
    set publicKey(pubkey){
        this._publicKey = this._deserializeKeyPair(pubkey);
    }
    set privateKey(prikey){
        this._privateKey = this._deserializeKeyPair(prikey);
    }
    generateKeyPair(bits=2048n){
        var [p, q] = this._getTwoPrimes(bits);
        var n = p*q;
        var lambda_n = RSA.lcm(p - 1n, q - 1n);
        var e = this._getE(lambda_n, p, q);
        var [k, d, r] = this._extendedEuclidean(lambda_n, e);

        if(r !== 1n) throw 'extendedEuclidean fall.';
        if(d < 0n) {
            d = d % lambda_n;
            d += lambda_n;
        }
        if(!this._isKeyPairSafe(p, q, n, e, d, bits)) console.warn('the keypair are not safe.');
        this._privateKey = [d, n];
        this._publicKey = [e, n];
        return {
            publicKey: this._publicKey,
            privateKey:　this._privateKey
        };
    }
    encrypt(M){
        var [e, n] = this._publicKey;
        var C, M;
        M = this._paddingSplit(M);
        M = this._splitByN(M, n);

        var _len, _arr;
        
        _len = M.length, C = Array(_len);
        var max = 0;
        for(var i=0; i<_len; i++){
            var m, c;
            m = M[i];
            m = this._arr2bint(m);
            c = RSA.modExp(m, e, n);
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
    decrypt(C){
        var [d, n] = this._privateKey;
        var M, C;
        
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
            m = RSA.modExp(c, d, n);
            m = this._bint2arr(m);
            M[i] = m;
        }
        
        M = this._flatArray(M);
        M = this._unpaddingSplit(M);
        return M;
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

    _serializeKeyPair(k){
        const chunkSize = RSA.PADDING_N;
        
        var [e, n] = k;
        [e, n] = [this._bint2arr(e), this._bint2arr(n)];
        [e, n] = [this._paddingSplit(e), this._paddingSplit(n)];
        
        var resArr = new Uint8Array(1 + e.length + n.length); //[e.length, e.arr, n.arr]
        var i = 0;
        resArr[i++] = Math.floor(e.length / chunkSize);
        for(var j = 0; j < e.length; i++, j++){
            resArr[i] = e[j];
        }
        for(var j = 0; j < n.length; i++, j++){
            resArr[i] = n[j];
        }
        
        return resArr;
    }
    _deserializeKeyPair(k){
        var pubkey = k;
        const chunkSize = RSA.PADDING_N;
        var eSize = pubkey[0];
        var e = pubkey.slice(1, 1 + eSize*chunkSize);
        var n = pubkey.slice(1 + eSize*chunkSize);
        e = this._unpaddingSplit(e);
        n = this._unpaddingSplit(n);
        e = this._arr2bint(e);
        n = this._arr2bint(n);
        return [e, n];
    }

    _paddingSplit(message){//split array to 24 length
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
        const sha256 = SHA256.instance;
        const [G, H] = [sha256.encode.bind(sha256), sha256.encode.bind(sha256)];

        m = this._paddingZeros(m, k1); // padding k1 zeros
        
        var r = crypto.getRandomValues(new Uint8Array(k0));
        var X = this._xorArray(m,  G(r)); //assert X.length === n - k0;
        var Y = this._xorArray(r, H(X));

        return this._concatArray(X, Y);
    }
    _unpadding(R){//output length: 24
        const n = RSA.PADDING_N, k0 = RSA.PADDING_K0, k1 = RSA.PADDING_K1;
        const sha256 = SHA256.instance;
        const [G, H] = [sha256.encode.bind(sha256), sha256.encode.bind(sha256)];
        
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
        var buffer = [];
        do{
            buffer.push(Number(bint%256n))
            bint >>= 8n;
        }while(bint>0);
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

    _getLowLevelPrime(n0, n1){
        /** Generate a prime candidate divisible by first primes*/
        while(true){
            // Obtain a random number
            var pc = RSA.randint(n0, n1);
            if((pc & 1n) === 0n) pc = pc + 1n;
            for(var divisor of RSA.FITST_PRIMES_LIST){
                if (pc % divisor === 0n && divisor*divisor <= pc)
                    break;
                else return pc;
            }
        }
    }
    
    _MillerTest(n){
        var d = n - 1n;
        var r = 0n;
        while(true){
            var r1 = (d>>1n);
            if(d !== r1<<1n) break;
            d = r1;
            r++;
        }

        var iter = 2n * RSA.log(n)**2n;
        iter = iter > n - 2n ? n - 2n : iter;
        for(var a=2n; a<iter; a++){
            var x = RSA.modExp(a, d, n);
            if(x === 1n || x === n - 1n)
                continue;
            var _toContinue = false;
            for(var j = 0n; j < r-1n; j++){
                x = x*x % n;
                if(x === n - 1n) {
                    _toContinue = true;
                    break;
                }
            }
            if(_toContinue) continue;
            return false;
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
            if (!this._MillerTest(prime_candidate))
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
            if(this._MillerTest(prime) && prime < lambda_n && lambda_n % e !== 0/*since e is prime*/){
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

// var rsa = new RSA();
// var keypair = rsa.generateKeyPair(10n);