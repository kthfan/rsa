/**
 * Modify from https://geraintluff.github.io/sha256/
 */


 export class SHA256{
    static _instance;
    MAX_WORD = 4294967296;
    HASH = new Int32Array(64);
    K = new Int32Array(64);

    static get instance(){
        if (SHA256._instance == null)
        {
            SHA256._instance = new SHA256();
        }
        return SHA256._instance;
    }

    constructor(){
        var primeCounter = 0;
        const isComposite = new Uint16Array(313);
        const hash = this.HASH;
        const k = this.K;
        const maxWord = this.MAX_WORD;
        for (var candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (var i = 0; i < 313; i += candidate) {
                    isComposite[i] = candidate;
                }
                hash[primeCounter] = (candidate**0.5 * maxWord) | 0;
                k[primeCounter++] = (candidate**(1/3) * maxWord) | 0;
            }
        }
    }
    _rightRotate(value, amount) {
		return (value>>>amount) | (value<<(32 - amount));
	};
    encode(byteArr){
        var hash = this.HASH;
        const k = this.K;
        const maxWord = this.MAX_WORD;

        var words;
        var byteArrLength;
        var byteArrBitLength = byteArr.length*8;
        var result = new Uint8Array(32);

        var _remainder = (byteArr.length + 1) % 64;
        if(_remainder > 56) _remainder = 64 - _remainder + 56;
        else _remainder = 56 - _remainder;
        var _tempByteArr = new Uint8Array(byteArr.length + 1 + _remainder);
        var _offset = 0;
        for(var i=0; i<byteArr.length; i++, _offset++){
            _tempByteArr[_offset] = byteArr[i];
        }
        _tempByteArr[_offset++] = 0x80;
        for(var i=0; i<_remainder; i++, _offset++){
            _tempByteArr[_offset] = 0;
        }
        byteArr = _tempByteArr;
        

        byteArrLength = byteArr.length;
        const _preWordLength = (byteArrLength>>2)+2;
        words = new Int32Array(_preWordLength);
        for (var i = 0; i < byteArrLength; i++) {
            var j = byteArr[i];
            if (j>>8) throw 'only accept number in range 0-255'; // ASCII check: only accept characters in range 0-255
            words[i>>2] |= j << ((3 - i)%4)*8;
            
        }
        words[(byteArrLength>>2)] = ((byteArrBitLength/maxWord)|0);
        words[(byteArrLength>>2)+1] = (byteArrBitLength);

        // process each chunk
        for (var j = 0; j < words.length;) {
            var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
            var _arr = new Int32Array(64);
            for(var i=0; i<w.length; i++){
                _arr[i] = w[i];
            }
            w = _arr;
            
            var oldHash = hash;
            // This is now the undefinedworking hash", often labelled as variables a...g
            // (we have to truncate as well, otherwise extra entries at the end accumulate
            hash = hash.slice(0, 8);
            _arr = new Int32Array(72);
            for(var i=64; i<72; i++)
                _arr[i] = hash[i-64];
            hash = _arr;

            for (var i = 0; i < 64; i++) {
                var i2 = i + j;
                var iHash = 64 - i;
                // Expand the message into 64 words
                // Used below if 
                
                // Iterate
                var a = hash[0+iHash], e = hash[4+iHash];
                var _num1 = (this._rightRotate(e, 6) ^ this._rightRotate(e, 11) ^ this._rightRotate(e, 25)); // S1
                var _num2 = ((e&hash[5+iHash])^((~e)&hash[6+iHash])); // ch
                
                if(i >= 16){ // Expand the message schedule if needed
                    var w15 = w[i - 15], w2 = w[i - 2];
                    var _num11 = (this._rightRotate(w15, 7) ^ this._rightRotate(w15, 18) ^ (w15>>>3)); // s0
                    var _num12 =  (this._rightRotate(w2, 17) ^ this._rightRotate(w2, 19) ^ (w2>>>10)); // s1
                    w[i] = (w[i - 16] + _num11 + w[i - 7] + _num12) | 0;
                }
                var temp1 = hash[7+iHash] + _num1 + _num2 + k[i] + w[i];
                

                // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
                var _num3 = (this._rightRotate(a, 2) ^ this._rightRotate(a, 13) ^ this._rightRotate(a, 22)); // S0
                var _num4 =  ((a&hash[1+iHash])^(a&hash[2+iHash])^(hash[1+iHash]&hash[2+iHash])); // maj
                var temp2 = _num3 + _num4;

                // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
            
                hash[iHash-1] = (temp1 + temp2) | 0;
                
                iHash--;
                hash[4+iHash] = (hash[4+iHash] + temp1)|0;
            }
            
            for (var i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i])|0;
            }
        }

        var offset = 0;
        for (var i = 0; i < 8; i++) {
            for (var j = 3; j + 1; j--) {
                var b = (hash[i]>>(j*8))&255;
                result[offset++] = b;
            }
        }
        return result;
    }
}
