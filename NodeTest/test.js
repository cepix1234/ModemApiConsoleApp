/*
SCRAMJS v1.0.1
Copyright © 2016 Technologies Co., Ltd. All rights reserved.
*/

// Shortcuts

const CryptoJS = require("crypto-js")

var C = CryptoJS;
var C_lib = C.lib;
var WordArray = C_lib.WordArray;
var C_algo = C.algo;

var SHA2    = C_algo.SHA256;
var HmacSHA2 = C.HmacSHA256;
var Base = C_lib.Base;

var SCRAM  = C_algo.SCRAM = Base.extend({
	cfg: Base.extend({
		keySize: 8,
		hasher: SHA2,
		hmac: HmacSHA2
	}),

	init: function (cfg) {
		this.cfg = this.cfg.extend(cfg);
	},
	/**
	 *  return client nonce
	 */
	nonce: function() {
		lastNonce = WordArray.random(this.cfg.keySize * 4);
		return lastNonce;
	},
	/**
	 * pbkdf2
	 */
	saltedPassword: function(password, salt, iterations) {
		return CryptoJS.PBKDF2(password, salt, {
			keySize: this.cfg.keySize,
			iterations:iterations,
			hasher: this.cfg.hasher
		});
	},
	/**
	 *   ClientKey = HMAC(saltPwd, "Client Key")
	 */
	clientKey: function(saltPwd) {
		return this.cfg.hmac(saltPwd, "Client Key");
	},
	/**
	 *   ServerKey = HMAC(saltPwd, "Server Key")
	 */
	serverKey: function(saltPwd) {
		return this.cfg.hmac(saltPwd, "Server Key");
	},
	/**
	 *   StoredKey = HASH(ClientKey)
	 */
	storedKey: function(clientKey) {
		var hasher = this.cfg.hasher.create();
		hasher.update(clientKey);

		return hasher.finalize();
	},
	/**
	 *   Signature = HMAC(StoredKey, AuthMessage)
	 */
	signature: function(storedKey, authMessage) {
		return this.cfg.hmac(storedKey, authMessage);
	},
	/**
	 *   ClientProof = ClientKey ^ ClientSignature
	 */
	clientProof: function (password, salt, iterations, authMessage) {
		var spwd = this.saltedPassword(password, salt, iterations);
		var ckey = this.clientKey(spwd);
		var skey = this.storedKey(ckey);
		var csig = this.signature(skey, authMessage);

		// words[1] = 1011111100010100011100101

		for (var i = 0; i < ckey.sigBytes/4; i += 1) {
			ckey.words[i] = ckey.words[i] ^ csig.words[i]
		}
		return ckey.toString();
	}
});

/**
 *   var scram = CryptoJS.SCRAM();
 */
C.SCRAM = function (cfg) {
	return SCRAM.create(cfg);
};

var password = "testPassword123"
var salt = CryptoJS.enc.Hex.parse("a058795da8a71336271577598a10bd4267e51b36f70594e824640bf7a37b17f9")
var iterations = 1000
var authMessage = "a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69,a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69IB07VhGRTZ0h6uY4RDjl0vCZNIJqc2CZ,a825e633d7d46b10dc8a0c9b41bc3173f64187789425e7ff2ecce95232021d69IB07VhGRTZ0h6uY4RDjl0vCZNIJqc2CZ"


scramTest = C.SCRAM()
const clientProof = scramTest.clientProof(password, salt, iterations, authMessage)
console.log(`Resulting Client Proof: ${clientProof}`)
