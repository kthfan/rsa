/**
 * Modify from https://geraintluff.github.io/sha256/
 */


class SHA256{
    static _instance;
    MAX_WORD = 1 <<32;
    HASH = [];
    K = [];

    static get instance(){
        if (SHA256._instance == null)
        {
            SHA256._instance = new SHA256();
        }
        return SHA256._instance;
    }

    constructor(){
        var primeCounter = 0;
        const isComposite = {};
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
    encode(ascii){
        var hash = this.HASH;
        const k = this.K;
        const maxWord = this.MAX_WORD;

        var words = [];
        var asciiLength;
        var asciiBitLength = ascii.length*8;
        var result = [];

        ascii = Array.from(ascii);
        ascii.push(0x80); // Append Ƈ' bit (plus zero padding)
        while (ascii.length%64 - 56) ascii.push(0); // More zero padding
        // ascii = new Uint8Array(ascii);

        asciiLength = ascii.length;
        for (var i = 0; i < ascii.length; i++) {
            var j = ascii[i];
            if (j>>8) throw 'only accept number in range 0-255'; // ASCII check: only accept characters in range 0-255
            words[i>>2] |= j << ((3 - i)%4)*8;
        }
        words[words.length] = ((asciiBitLength/maxWord)|0);
        words[words.length] = (asciiBitLength)


        // process each chunk
        for (var j = 0; j < words.length;) {
            var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
            var oldHash = hash;
            // This is now the undefinedworking hash", often labelled as variables a...g
            // (we have to truncate as well, otherwise extra entries at the end accumulate
            hash = hash.slice(0, 8);
            
            for (var i = 0; i < 64; i++) {
                var i2 = i + j;
                // Expand the message into 64 words
                // Used below if 
                var w15 = w[i - 15], w2 = w[i - 2];

                // Iterate
                var a = hash[0], e = hash[4];
                var temp1 = hash[7]
                    + (this._rightRotate(e, 6) ^ this._rightRotate(e, 11) ^ this._rightRotate(e, 25)) // S1
                    + ((e&hash[5])^((~e)&hash[6])) // ch
                    + k[i]
                    // Expand the message schedule if needed
                    + (w[i] = (i < 16) ? w[i] : (
                            w[i - 16]
                            + (this._rightRotate(w15, 7) ^ this._rightRotate(w15, 18) ^ (w15>>>3)) // s0
                            + w[i - 7]
                            + (this._rightRotate(w2, 17) ^ this._rightRotate(w2, 19) ^ (w2>>>10)) // s1
                        )|0
                    );
                // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
                var temp2 = (this._rightRotate(a, 2) ^ this._rightRotate(a, 13) ^ this._rightRotate(a, 22)) // S0
                    + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj
                
                hash = [(temp1 + temp2)|0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
                hash[4] = (hash[4] + temp1)|0;
            }
            
            for (var i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i])|0;
            }
        }

        for (var i = 0; i < 8; i++) {
            for (var j = 3; j + 1; j--) {
                var b = (hash[i]>>(j*8))&255;
                result.push(b);
            }
        }
        return new Uint8Array(result);
    }
}

