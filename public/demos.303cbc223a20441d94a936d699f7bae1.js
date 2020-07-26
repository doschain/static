(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeAddress = exports.encodePKAddress = exports.encodeAddress = exports.AddressScriptHash = exports.AddressSecpPubKey = exports.AddressPubKeyHash = exports.Address = void 0;
const chaincfg_1 = require("@demos/chaincfg");
const dosec_1 = require("@demos/dosec");
const bs58check_1 = require("@demos/bs58check");
class Address {
    constructor(hash, net) {
        this._hash = hash;
        this._net = net;
    }
    hash160() {
        return this._hash;
    }
    isForNet(net) {
        return net === this._net;
    }
    DSA() {
        return -1;
    }
    encode() {
        return "";
    }
    toString() {
        return this.encode();
    }
}
exports.Address = Address;
class AddressPubKeyHash extends Address {
    constructor(hash, net, algo) {
        super(hash, net);
        let addrID;
        switch (algo) {
            case dosec_1.SignatureType.STEcdsaSecp256k1:
                addrID = net.pubKeyHashAddrID;
                break;
            case dosec_1.SignatureType.STEd25519:
                addrID = net.pkhEdwardsAddrID;
                break;
            case dosec_1.SignatureType.STSchnorrSecp256k1:
                addrID = net.pkhSchnorrAddrID;
                break;
            default:
                throw new Error("unknown ECDSA algorithm");
        }
        this._netID = addrID;
    }
    encode() {
        return encodeAddress(this._hash, this._netID);
    }
    DSA() {
        if (this._net.pubKeyHashAddrID.equals(this._netID)) {
            return dosec_1.SignatureType.STEcdsaSecp256k1;
        }
        else if (this._net.pkhEdwardsAddrID.equals(this._netID)) {
            return dosec_1.SignatureType.STEd25519;
        }
        else if (this._net.pkhSchnorrAddrID.equals(this._netID)) {
            return dosec_1.SignatureType.STSchnorrSecp256k1;
        }
        return -1;
    }
}
exports.AddressPubKeyHash = AddressPubKeyHash;
class AddressSecpPubKey extends Address {
    constructor(hash, net) {
        super(hash, net);
    }
    encode() {
        return encodePKAddress(this._hash, this._net.pubKeyAddrID, dosec_1.SignatureType.STEcdsaSecp256k1);
    }
}
exports.AddressSecpPubKey = AddressSecpPubKey;
class AddressScriptHash extends Address {
    constructor(hash, net) {
        super(hash, net);
    }
    encode() {
        return encodeAddress(this._hash, this._net.scriptHashAddrID);
    }
}
exports.AddressScriptHash = AddressScriptHash;
function encodeAddress(hash, netID) {
    return bs58check_1.encode(Buffer.concat([netID, hash], netID.length + hash.length));
}
exports.encodeAddress = encodeAddress;
function encodePKAddress(hash, netID, algo) {
    let pubKeyBytes = Buffer.alloc(1);
    switch (algo) {
        case dosec_1.SignatureType.STEcdsaSecp256k1:
            pubKeyBytes.writeUInt8(algo);
            break;
        default:
            pubKeyBytes.writeUInt8(0);
            break;
    }
    let compressed = Buffer.from(hash);
    if (algo == dosec_1.SignatureType.STEcdsaSecp256k1 || algo == dosec_1.SignatureType.STSchnorrSecp256k1) {
        if (compressed[0] == 0x03) {
            compressed[0] |= (1 << 7);
        }
        compressed = compressed.slice(1);
    }
    let buffer = Buffer.concat([netID, Buffer.concat([pubKeyBytes, compressed])]);
    return bs58check_1.encode(buffer);
}
exports.encodePKAddress = encodePKAddress;
function decodeAddress(address) {
    let payload;
    try {
        payload = bs58check_1.decode(address);
    }
    catch (_) {
        throw new Error("decoded address is of unknown");
    }
    let netID = payload.version;
    let de = payload.decode;
    let net = _detectNetworkForAddress(address);
    if (netID.equals(net.pubKeyHashAddrID)) {
        return new AddressPubKeyHash(de, net, dosec_1.SignatureType.STEcdsaSecp256k1);
    }
    else if (netID.equals(net.scriptHashAddrID)) {
        return new AddressScriptHash(de, net);
    }
    else if (netID.equals(net.pubKeyAddrID)) {
        return new AddressSecpPubKey(de, net);
    }
    throw new Error("unknown address type");
}
exports.decodeAddress = decodeAddress;
function _detectNetworkForAddress(address) {
    if (address.length < 1) {
        throw new Error("empty string given for network detection");
    }
    let networkChar = address.substring(0, 1);
    if (networkChar === chaincfg_1.mainnet.networkAddressPrefix) {
        return chaincfg_1.mainnet;
    }
    else if (networkChar === chaincfg_1.testnet3.networkAddressPrefix) {
        return chaincfg_1.testnet3;
    }
    throw new Error("unknown network type");
}

}).call(this,require("buffer").Buffer)
},{"@demos/bs58check":2,"@demos/chaincfg":3,"@demos/dosec":17,"buffer":62}],2:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = exports.decodeUnsafe = exports.encode = void 0;
const chainhash_1 = require("@demos/chainhash");
const base58 = require('bs58');
function checksumFn(buffer) {
    return chainhash_1.hashB(chainhash_1.hashB(buffer));
}
function encode(payload) {
    let checksum = checksumFn(payload);
    return base58.encode(Buffer.concat([
        payload,
        checksum
    ], payload.length + 4));
}
exports.encode = encode;
function decodeRaw(buffer) {
    let payload = buffer.slice(0, -4);
    let checksum = buffer.slice(-4);
    let newChecksum = checksumFn(payload);
    if (checksum[0] ^ newChecksum[0] |
        checksum[1] ^ newChecksum[1] |
        checksum[2] ^ newChecksum[2] |
        checksum[3] ^ newChecksum[3]) {
        throw new Error('Invalid checksum');
    }
    return payload;
}
function decodeUnsafe(str) {
    let buffer = base58.decodeUnsafe(str);
    if (!buffer) {
        throw new Error('decoded address is of unknown');
    }
    return decodeRaw(buffer);
}
exports.decodeUnsafe = decodeUnsafe;
function decode(str) {
    let buffer = base58.decode(str);
    let ret = decodeRaw(buffer);
    let decode = ret.slice(2);
    let version = buffer.slice(0, 2);
    if (!decode)
        throw new Error('Invalid checksum');
    return {
        decode,
        version
    };
}
exports.decode = decode;

}).call(this,require("buffer").Buffer)
},{"@demos/chainhash":4,"bs58":61,"buffer":62}],3:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.testnet3 = exports.mainnet = exports.Params = void 0;
class Params {
    constructor(cfg) {
        this._name = cfg.name;
        this._networkAddressPrefix = cfg.networkAddressPrefix;
        this._pubKeyAddrID = cfg.pubKeyAddrID;
        this._pubKeyHashAddrID = cfg.pubKeyHashAddrID;
        this._pkhEdwardsAddrID = cfg.pkhEdwardsAddrID;
        this._pkhSchnorrAddrID = cfg.pkhSchnorrAddrID;
        this._scriptHashAddrID = cfg.scriptHashAddrID;
        this._privateKeyID = cfg.privateKeyID;
        this._hdPrivateKeyID = cfg.hdPrivateKeyID;
        this._hdPublicKeyID = cfg.hdPublicKeyID;
        this._slip0044CoinType = cfg.slip0044CoinType;
        this._legacyCoinType = cfg.legacyCoinType;
        this._stakeDiffWindowSize = cfg.stakeDiffWindowSize;
        this._ticketPoolSize = cfg.ticketPoolSize;
        this._subsidyReductionInterval = cfg.subsidyReductionInterval;
        this._workRewardProportion = cfg.workRewardProportion;
        this._stakeRewardProportion = cfg.stakeRewardProportion;
        this._blockTaxProportion = cfg.blockTaxProportion;
        this._baseSubsidy = cfg.baseSubsidy;
        this._mulSubsidy = cfg.mulSubsidy;
        this._divSubsidy = cfg.divSubsidy;
        this._ticketsPerBlock = cfg.ticketsPerBlock;
    }
    get name() {
        return this._name;
    }
    get networkAddressPrefix() {
        return this._networkAddressPrefix;
    }
    get pubKeyAddrID() {
        return this._pubKeyAddrID;
    }
    get pubKeyHashAddrID() {
        return this._pubKeyHashAddrID;
    }
    get pkhEdwardsAddrID() {
        return this._pkhEdwardsAddrID;
    }
    get pkhSchnorrAddrID() {
        return this._pkhSchnorrAddrID;
    }
    get scriptHashAddrID() {
        return this._scriptHashAddrID;
    }
    get privateKeyID() {
        return this._privateKeyID;
    }
    get hdPrivateKeyID() {
        return this._hdPrivateKeyID;
    }
    get hdPublicKeyID() {
        return this._hdPublicKeyID;
    }
    get slip0044CoinType() {
        return this._slip0044CoinType;
    }
    get legacyCoinType() {
        return this._legacyCoinType;
    }
    get stakeDiffWindowSize() {
        return this._stakeDiffWindowSize;
    }
    get ticketPoolSize() {
        return this._ticketPoolSize;
    }
    get subsidyReductionInterval() {
        return this._subsidyReductionInterval;
    }
    get workRewardProportion() {
        return this._workRewardProportion;
    }
    get stakeRewardProportion() {
        return this._stakeRewardProportion;
    }
    get blockTaxProportion() {
        return this._blockTaxProportion;
    }
    get baseSubsidy() {
        return this._baseSubsidy;
    }
    get mulSubsidy() {
        return this._mulSubsidy;
    }
    get divSubsidy() {
        return this._divSubsidy;
    }
    get ticketsPerBlock() {
        return this._ticketsPerBlock;
    }
    blockOneSubsidy() {
        return 0;
    }
    totalSubsidyProportions() {
        return this._workRewardProportion + this._stakeRewardProportion + this._blockTaxProportion;
    }
}
exports.Params = Params;
exports.mainnet = new Params({
    name: "mainnet",
    networkAddressPrefix: "S",
    pubKeyAddrID: Buffer.from([0x27, 0x6D]),
    pubKeyHashAddrID: Buffer.from([0x0E, 0x6B]),
    pkhEdwardsAddrID: Buffer.from([0x0E, 0x70]),
    pkhSchnorrAddrID: Buffer.from([0x0E, 0x90]),
    scriptHashAddrID: Buffer.from([0x0E, 0x2F]),
    privateKeyID: Buffer.from([0x22, 0xde]),
    hdPrivateKeyID: Buffer.from([0x04, 0x20, 0xb9, 0x03]),
    hdPublicKeyID: Buffer.from([0x04, 0x20, 0xbd, 0x3d]),
    slip0044CoinType: 42,
    legacyCoinType: 20,
    stakeDiffWindowSize: 144,
    ticketPoolSize: 8192,
    subsidyReductionInterval: 6144,
    workRewardProportion: 1,
    stakeRewardProportion: 89,
    blockTaxProportion: 10,
    baseSubsidy: 33908497845,
    mulSubsidy: 100,
    divSubsidy: 101,
    ticketsPerBlock: 5
});
exports.testnet3 = new Params({
    name: "testnet3",
    networkAddressPrefix: "T",
    pubKeyAddrID: Buffer.from([0x28, 0xf7]),
    pubKeyHashAddrID: Buffer.from([0x0e, 0xfb]),
    pkhEdwardsAddrID: Buffer.from([0x0f, 0x01]),
    pkhSchnorrAddrID: Buffer.from([0x0e, 0xe3]),
    scriptHashAddrID: Buffer.from([0x0e, 0xbf]),
    privateKeyID: Buffer.from([0x23, 0x0e]),
    hdPrivateKeyID: Buffer.from([0x04, 0x35, 0x83, 0x97]),
    hdPublicKeyID: Buffer.from([0x04, 0x35, 0x87, 0xd1]),
    slip0044CoinType: 1,
    legacyCoinType: 11,
    stakeDiffWindowSize: 144,
    ticketPoolSize: 1024,
    subsidyReductionInterval: 2048,
    workRewardProportion: 6,
    stakeRewardProportion: 3,
    blockTaxProportion: 1,
    baseSubsidy: 2500000000,
    mulSubsidy: 100,
    divSubsidy: 101,
    ticketsPerBlock: 5
});

}).call(this,require("buffer").Buffer)
},{"buffer":62}],4:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashH = exports.hashB = exports.Hash = void 0;
const createBlakeHash = require("blake-hash");
let Hash = /** @class */ (() => {
    class Hash {
        constructor(hash) {
            this._hash = hash;
        }
        toString() {
            let hash = this.cloneBytes();
            for (let i = 0; i < Hash.HASH_SIZE / 2; i++) {
                [hash[i], hash[Hash.HASH_SIZE - 1 - i]] = [hash[Hash.HASH_SIZE - 1 - i], hash[i]];
            }
            return Buffer.prototype.toString.call(hash, "hex");
        }
        cloneBytes() {
            return Buffer.from(this._hash);
        }
        equal(otherHash) {
            if (!this._hash && !otherHash) {
                return true;
            }
            if (!this._hash || !otherHash) {
                return false;
            }
            return this._hash.equals(otherHash.cloneBytes());
        }
        static fromString(hash) {
            return decode(hash);
        }
    }
    Hash.HASH_SIZE = 32;
    Hash.MAX_HASH_STRING_SIZE = 32 * 2;
    return Hash;
})();
exports.Hash = Hash;
function decode(src) {
    if (!src || src.length > Hash.MAX_HASH_STRING_SIZE) {
        throw new Error(`max hash string length is ${Hash.MAX_HASH_STRING_SIZE} bytes`);
    }
    let len = src.length;
    let srcBytes = Buffer.from(src, 'hex');
    if (len % 2 != 0) {
        let bytes = Buffer.allocUnsafe(len + 1);
        bytes.fill(0);
        bytes.writeUInt8(0, 0);
        srcBytes.copy(bytes, 1);
        srcBytes = bytes;
    }
    let reversedHash = Buffer.allocUnsafe(srcBytes.length);
    for (let i = 0; i < Hash.HASH_SIZE / 2; i++) {
        [reversedHash[i], reversedHash[Hash.HASH_SIZE - 1 - i]] = [srcBytes[Hash.HASH_SIZE - 1 - i], srcBytes[i]];
    }
    return new Hash(reversedHash);
}
function hashB(data) {
    return createBlakeHash('blake256').update(data).digest();
}
exports.hashB = hashB;
function hashH(data) {
    return new Hash(hashB(data));
}
exports.hashH = hashH;

}).call(this,require("buffer").Buffer)
},{"blake-hash":50,"buffer":62}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContractABI = void 0;
const function_parameter_1 = require("./function_parameter");
const address_1 = require("./types/address");
const function_1 = require("./types/function");
const bool_1 = require("./types/bool");
const static_length_bytes_1 = require("./types/static_length_bytes");
const uint_1 = require("./types/uint");
const string_1 = require("./types/string");
const dynamic_length_bytes_1 = require("./types/dynamic_length_bytes");
class ContractABI {
    static parseParameters(data) {
        if (!data || !data.length) {
            return [];
        }
        let elements = [];
        for (let ele of data) {
            let name = ele.name;
            let type = ele.type;
            elements.push(new function_parameter_1.FunctionParameter(name, ContractABI.parseType(type)));
        }
        return elements;
    }
    /**
     * @param {String} type
     * @return {ABIType}
     */
    static parseType(type) {
        if (type.match(/^uint/)) {
            if (type.length === 4) {
                return new uint_1.UintType();
            }
            let M = parseInt(type.substring(4));
            return new uint_1.UintType(M);
        }
        else if (type.match(/^bytes/)) {
            if (type.length === 5) {
                return new dynamic_length_bytes_1.DynamicLengthBytes();
            }
            let length = parseInt(type.substring(5));
            return new static_length_bytes_1.StaticLengthBytes(length);
        }
        switch (type) {
            case "string":
                return new string_1.StringType();
            case "address":
                return new address_1.AddressType();
            case "function":
                return new function_1.FunctionType();
            case "bool":
                return new bool_1.BoolType();
            default:
                throw new Error(`Unsupported type: ${type}`);
        }
    }
}
exports.ContractABI = ContractABI;

},{"./function_parameter":8,"./types/address":10,"./types/bool":11,"./types/dynamic_length_bytes":12,"./types/function":13,"./types/static_length_bytes":14,"./types/string":15,"./types/uint":16}],6:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./types/abi_type"), exports);
__exportStar(require("./abi"), exports);
__exportStar(require("./function"), exports);
__exportStar(require("./function_parameter"), exports);

},{"./abi":5,"./function":7,"./function_parameter":8,"./types/abi_type":9}],7:[function(require,module,exports){
(function (Buffer){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContractFunction = void 0;
const sha3_1 = require("sha3");
const bn_js_1 = __importDefault(require("bn.js"));
const uint_1 = require("./types/uint");
class ContractFunction {
    constructor(name, parameters) {
        this._name = name;
        this._parameters = parameters;
    }
    encodeName() {
        let parameterTypes = this._parameters.map((p) => p.type.name).join(",");
        return `${this._name}(${parameterTypes})`;
    }
    encode(params) {
        let parameters = this._parameters;
        if (params.length !== parameters.length) {
            throw new Error(`Must match function parameters: ${params.length}`);
        }
        let startHash = sha3(Buffer.from(this.encodeName())).slice(0, 4);
        let finishedEncodings = [];
        let dynamicEncodings = [];
        for (let i = 0; i < parameters.length; i++) {
            let parameter = parameters[i];
            let value = params[i];
            let encoded = parameter.type.encode(value);
            if (parameter.type.isDynamic) {
                dynamicEncodings.push(encoded);
                finishedEncodings.push(("").padStart(64, "0")); //will be set later
            }
            else {
                finishedEncodings.push(encoded);
            }
        }
        let currentOffset = finishedEncodings.reduce((ret, val) => ret + Math.floor(val.length / 2), 0);
        let dynamicParam = parameters.filter(k => k.type.isDynamic);
        dynamicParam.forEach(param => {
            let index = parameters.indexOf(param);
            finishedEncodings[index] = new uint_1.UintType().encode(new bn_js_1.default(currentOffset));
            let firstDynamicEncoding = dynamicEncodings.shift();
            if (firstDynamicEncoding === undefined)
                return;
            finishedEncodings.push(firstDynamicEncoding);
            currentOffset += Math.floor(firstDynamicEncoding.length / 2);
        });
        return startHash.toString("hex") + finishedEncodings.join("");
    }
    decode(data) {
        data = data.substr(8);
        let parameters = this._parameters;
        let result = [];
        for (let i = 0; i < parameters.length; i++) {
            let parameter = parameters[i];
            let decode;
            [decode, data] = parameter.type.decode(data);
            result.push(decode);
        }
        return result;
    }
}
exports.ContractFunction = ContractFunction;
function sha3(data) {
    let hash = new sha3_1.Keccak(256);
    hash.update(data);
    return hash.digest();
}

}).call(this,require("buffer").Buffer)
},{"./types/uint":16,"bn.js":59,"buffer":62,"sha3":83}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FunctionParameter = void 0;
class FunctionParameter {
    constructor(name, type) {
        this._name = name;
        this._type = type;
    }
    get name() {
        return this._name;
    }
    get type() {
        return this._type;
    }
}
exports.FunctionParameter = FunctionParameter;

},{}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ABIType = void 0;
class ABIType {
    constructor(name, dynamic = false) {
        this._name = name;
        this._dynamic = dynamic;
    }
    get name() {
        return this._name;
    }
    get isDynamic() {
        return this._dynamic;
    }
    encode(data) {
        return "";
    }
    decode(data) {
        return [];
    }
    calculatePadLen(actualLength) {
        let mod = actualLength % ABIType.SIZE_UNIT_HEX;
        return mod === 0 && actualLength > 0 ? 0 : ABIType.SIZE_UNIT_HEX - mod;
    }
}
exports.ABIType = ABIType;
ABIType.SIZE_UNIT_BYTES = 32;
ABIType.SIZE_UNIT_HEX = 64;

},{}],10:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AddressType = void 0;
const uint_1 = require("./uint");
const bn_js_1 = __importDefault(require("bn.js"));
const address_1 = require("@demos/address");
class AddressType extends uint_1.UintType {
    constructor() {
        super(160);
        this._name = "address";
    }
    encode(data) {
        if (typeof data === "string") {
            let addr = address_1.decodeAddress(data);
            let hash = addr.hash160();
            return super.encode(new bn_js_1.default(hash));
        }
        return super.encode(data);
    }
}
exports.AddressType = AddressType;

},{"./uint":16,"@demos/address":1,"bn.js":59}],11:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BoolType = void 0;
const abi_type_1 = require("./abi_type");
class BoolType extends abi_type_1.ABIType {
    constructor() {
        super("bool");
    }
    encode(data) {
        return (data ? "1" : "0").padStart(abi_type_1.ABIType.SIZE_UNIT_HEX - 1, "0");
    }
    decode(data) {
        return [data[abi_type_1.ABIType.SIZE_UNIT_HEX - 1] == '1', data.substring(abi_type_1.ABIType.SIZE_UNIT_HEX)];
    }
}
exports.BoolType = BoolType;

},{"./abi_type":9}],12:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DynamicLengthBytes = void 0;
const static_length_bytes_1 = require("./static_length_bytes");
const uint_1 = require("./uint");
const bn_js_1 = __importDefault(require("bn.js"));
const abi_type_1 = require("./abi_type");
class DynamicLengthBytes extends abi_type_1.ABIType {
    constructor() {
        super("bytes", true);
    }
    encode(bytes) {
        let length = bytes.length;
        let dataEncoded = new static_length_bytes_1.StaticLengthBytes(length, true).encode(bytes);
        return new uint_1.UintType().encode(new bn_js_1.default(length)) + dataEncoded;
    }
    decode(data) {
        let decodedLength = new uint_1.UintType().decode(data);
        let length = decodedLength[0].toNumber();
        data = decodedLength[1];
        return new static_length_bytes_1.StaticLengthBytes(length, true).decode(data);
    }
}
exports.DynamicLengthBytes = DynamicLengthBytes;

},{"./abi_type":9,"./static_length_bytes":14,"./uint":16,"bn.js":59}],13:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FunctionType = void 0;
const static_length_bytes_1 = require("./static_length_bytes");
class FunctionType extends static_length_bytes_1.StaticLengthBytes {
    constructor() {
        super(24);
        this._name = "function";
    }
}
exports.FunctionType = FunctionType;

},{"./static_length_bytes":14}],14:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StaticLengthBytes = void 0;
const abi_type_1 = require("./abi_type");
class StaticLengthBytes extends abi_type_1.ABIType {
    constructor(length, ignoreLength = false) {
        if (!ignoreLength && (length <= 0 || length > 32))
            throw new Error("Length of static byte array must be between 0 and 32, was $length");
        super(`bytes${length}`);
        this._length = length;
    }
    encode(data) {
        if (!Buffer.isBuffer(data)) {
            data = Buffer.from(data);
        }
        if (data.length !== this._length) {
            throw new Error(`Length of bytes did not match. (Expected ${this._length}, got ${data.length})`);
        }
        let encoded = data.toString("hex");
        return encoded.padEnd(this.calculatePadLen(encoded.length), "0");
    }
    decode(data) {
        let encodedLength = Math.floor((this.calculatePadLen(length * 2) + length * 2) / 2);
        let modifiedData = data.substring(0, length * 2); //rest is right-padded with 0
        let bytes = Buffer.from(modifiedData, "hex");
        return [bytes, data.substring(encodedLength)];
    }
}
exports.StaticLengthBytes = StaticLengthBytes;

}).call(this,require("buffer").Buffer)
},{"./abi_type":9,"buffer":62}],15:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StringType = void 0;
const abi_type_1 = require("./abi_type");
const dynamic_length_bytes_1 = require("./dynamic_length_bytes");
class StringType extends abi_type_1.ABIType {
    constructor() {
        super("string", true);
    }
    encode(data) {
        return new dynamic_length_bytes_1.DynamicLengthBytes().encode(Buffer.from(data));
    }
    decode(data) {
        let decodedBytes = new dynamic_length_bytes_1.DynamicLengthBytes().decode(data);
        return [decodedBytes[0].toString(), decodedBytes[1]];
    }
}
exports.StringType = StringType;

}).call(this,require("buffer").Buffer)
},{"./abi_type":9,"./dynamic_length_bytes":12,"buffer":62}],16:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.UintType = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
const abi_type_1 = require("./abi_type");
class UintType extends abi_type_1.ABIType {
    constructor(M = 256) {
        super(`uint${M}`);
        if (M <= 0 || M > 256 || M % 8 !== 0) {
            throw new Error(`Invalid size argument: ${M}`);
        }
        this._maxValue = new bn_js_1.default(1).ishln(M);
    }
    encode(data) {
        if (!bn_js_1.default.isBN(data)) {
            data = new bn_js_1.default(data);
        }
        if (data.gt(this._maxValue)) {
            throw new Error(`Value to encode must be <= ${this._maxValue.toString()}, got ${data.toString()}`);
        }
        if (data.isNeg()) {
            throw new Error("Tried to encode negative number as an uint");
        }
        let hex = data.toString("hex");
        return hex.padStart(this.calculatePadLen(hex.length) + hex.length, "0");
    }
    decode(data) {
        let len = abi_type_1.ABIType.SIZE_UNIT_HEX;
        let ret = data.substring(0, len);
        return [new bn_js_1.default(ret, 16), data.substr(len)];
    }
}
exports.UintType = UintType;

},{"./abi_type":9,"bn.js":59}],17:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SignatureType = void 0;
var SignatureType;
(function (SignatureType) {
    SignatureType[SignatureType["STEcdsaSecp256k1"] = 0] = "STEcdsaSecp256k1";
    SignatureType[SignatureType["STEd25519"] = 1] = "STEd25519";
    SignatureType[SignatureType["STSchnorrSecp256k1"] = 2] = "STSchnorrSecp256k1";
})(SignatureType = exports.SignatureType || (exports.SignatureType = {}));

},{}],18:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthoredTx = exports.GENERATED_TX_VERSION = void 0;
const txsizes = __importStar(require("@demos/txsizes"));
const txrules = __importStar(require("@demos/txrules"));
const txscript = __importStar(require("@demos/txscript"));
const msg_tx_1 = require("./msg_tx");
const tx_out_1 = require("./tx_out");
const helper_1 = require("./helper");
exports.GENERATED_TX_VERSION = 1;
class AuthoredTx {
    constructor(tx, prevScripts, totalInput, changeIndex, estimatedSignedSerializeSize) {
        this.tx = tx;
        this.prevScripts = prevScripts;
        this.totalInput = totalInput;
        this.changeIndex = changeIndex;
        this.estimatedSignedSerializeSize = estimatedSignedSerializeSize;
    }
    static unsignedTransaction(outputs, relayFeePerKb, fetchInputs, fetchChange) {
        let targetAmount = helper_1.sumOutputValues(outputs);
        let scriptSizes = [txsizes.REDEEM_P2PKH_SIG_SCRIPT_SIZE];
        fetchChange.script();
        let changeScript = fetchChange.hash;
        let changeScriptVersion = fetchChange.version;
        let changeScriptSize = fetchChange.scriptSize();
        let maxSignedSize = txsizes.estimateSerializeSize(scriptSizes, outputs, changeScriptSize);
        let targetFee = txrules.feeForSerializeSize(relayFeePerKb, maxSignedSize);
        while (true) {
            let inputDetail = fetchInputs(targetAmount.add(targetFee));
            if (inputDetail.amount.compareTo(targetAmount.add(targetFee)) == -1) {
                throw new Error("insufficient balance");
            }
            let scriptSizes = inputDetail.redeemScriptSizes;
            maxSignedSize = txsizes.estimateSerializeSize(scriptSizes, outputs, changeScriptSize);
            let maxRequiredFee = txrules.feeForSerializeSize(relayFeePerKb, maxSignedSize);
            let remainingAmount = inputDetail.amount.sub(targetAmount);
            if (remainingAmount.compareTo(maxRequiredFee) == -1) {
                targetFee = maxRequiredFee;
                continue;
            }
            let unsignedTransaction = new msg_tx_1.MsgTx(undefined, msg_tx_1.TX_SERIALIZE_FULL, exports.GENERATED_TX_VERSION, inputDetail.inputs, outputs);
            let changeIndex = -1;
            let changeAmount = inputDetail.amount.sub(targetAmount).sub(maxRequiredFee);
            if (changeScript.length > txscript.MAX_SCRIPT_ELEMENT_SIZE) {
                throw new Error("script size exceed maximum bytes pushable to the stack");
            }
            let change = new tx_out_1.TxOut(changeAmount, changeScriptVersion, changeScript);
            outputs.push(change);
            unsignedTransaction.txOut = outputs;
            changeIndex = outputs.length;
            return new AuthoredTx(unsignedTransaction, inputDetail.scripts, inputDetail.amount, changeIndex, maxSignedSize);
        }
    }
}
exports.AuthoredTx = AuthoredTx;

},{"./helper":22,"./msg_tx":25,"./tx_out":31,"@demos/txrules":33,"@demos/txscript":44,"@demos/txsizes":45}],19:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.writeVarBytes = exports.copyBytes = exports.writeVarString = exports.writeVarInt = exports.readVarInt = void 0;
const MAX_UINT_16 = 1 << 16 - 1;
const MAX_UINT_32 = 1 << 32 - 1;
function readVarInt(buf, offset = 0) {
    let discriminant = buf.readInt8(offset);
    offset += 1;
    let rv, min = 0;
    switch (discriminant) {
        case 0xff:
            rv = buf.readUIntLE(offset, 8);
            offset += 8;
            min = 0x100000000;
            break;
        case 0xfe:
            rv = buf.readUInt32LE(offset);
            offset += 4;
            min = 0x10000;
            break;
        case 0xfd:
            rv = buf.readUInt16LE(offset);
            offset += 2;
            min = 0xfd;
            break;
        default:
            rv = discriminant;
            break;
    }
    if (rv < min) {
        throw new Error(`non-canonical varint ${rv} - discriminant ${discriminant} must encode a value greater than ${min}`);
    }
    return [rv, offset];
}
exports.readVarInt = readVarInt;
function writeVarInt(buf, val, offset = 0) {
    if (val < 0xfd) {
        buf.writeUInt8(val, offset);
        return offset + 1;
    }
    if (val <= MAX_UINT_16) {
        buf.writeUInt8(0xfd, offset);
        offset++;
        buf.writeUInt16LE(val, offset);
        return offset + 2;
    }
    if (val <= MAX_UINT_32) {
        buf.writeUInt8(0xfe, offset);
        offset++;
        buf.writeUInt32LE(val, offset);
        return offset + 4;
    }
    buf.writeUInt8(0xff, offset);
    offset++;
    buf.writeUIntLE(val, offset, 8);
    return offset + 8;
}
exports.writeVarInt = writeVarInt;
function writeVarString(buf, str, offset = 0) {
    offset = writeVarInt(buf, str.length, offset);
    let bytes = Buffer.from(str, 'utf8');
    offset = copyBytes(buf, bytes, offset);
    return offset;
}
exports.writeVarString = writeVarString;
function copyBytes(buf, bytes, offset = 0) {
    bytes.copy(buf, offset);
    return offset + bytes.length;
}
exports.copyBytes = copyBytes;
function writeVarBytes(buf, bytes, offset = 0) {
    offset = writeVarInt(buf, bytes.length, offset);
    return copyBytes(buf, bytes, offset);
}
exports.writeVarBytes = writeVarBytes;

}).call(this,require("buffer").Buffer)
},{"buffer":62}],20:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Credit = void 0;
class Credit {
    constructor(outPoint, amount, pkScript, fromCoinBase) {
        this._outPoint = outPoint;
        this._amount = amount;
        this._pkScript = pkScript;
        this._fromCoinBase = fromCoinBase;
    }
    get outPoint() {
        return this._outPoint;
    }
    get amount() {
        return this._amount;
    }
    get pkScript() {
        return this._pkScript;
    }
    get fromCoinBase() {
        return this._fromCoinBase;
    }
}
exports.Credit = Credit;

},{}],21:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtendedOutPoint = void 0;
class ExtendedOutPoint {
    constructor(op, amount, pkScript) {
        this._op = op;
        this._amount = amount;
        this._pkScript = pkScript;
    }
    get op() {
        return this._op;
    }
    get amount() {
        return this._amount;
    }
    get pkScript() {
        return this._pkScript;
    }
}
exports.ExtendedOutPoint = ExtendedOutPoint;

},{}],22:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sumOutputSerializeSizes = exports.sumOutputValues = exports.makeTxOutput = exports.makeTxOutputs = void 0;
const tx_out_1 = require("./tx_out");
const txscript_1 = require("@demos/txscript");
const address_1 = require("@demos/address");
const utils_1 = require("@demos/utils");
function makeTxOutputs(destinations) {
    let outputs = [];
    for (let i = 0; i < destinations.length; i++) {
        outputs.push(makeTxOutput(destinations[i]));
    }
    return outputs;
}
exports.makeTxOutputs = makeTxOutputs;
function makeTxOutput(destination) {
    let pkScript = txscript_1.payToAddrScript(address_1.decodeAddress(destination.address));
    let amountInAtom = new utils_1.Amount(destination.amount);
    return new tx_out_1.TxOut(amountInAtom, 0, pkScript);
}
exports.makeTxOutput = makeTxOutput;
function sumOutputValues(outputs) {
    let totalOutput = new utils_1.Amount(0);
    for (let i = 0; i < outputs.length; i++) {
        totalOutput = totalOutput.add(outputs[i].value);
    }
    return totalOutput;
}
exports.sumOutputValues = sumOutputValues;
function sumOutputSerializeSizes(outputs) {
    let serializeSize = 0;
    for (let i = 0; i < outputs.length; i++) {
        serializeSize += outputs[i].serializeSize();
    }
    return serializeSize;
}
exports.sumOutputSerializeSizes = sumOutputSerializeSizes;

},{"./tx_out":31,"@demos/address":1,"@demos/txscript":44,"@demos/utils":47}],23:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InputDetail = void 0;
class InputDetail {
    constructor(amount, inputs, scripts, redeemScriptSizes) {
        this.amount = amount;
        this.inputs = inputs;
        this.scripts = scripts;
        this.redeemScriptSizes = redeemScriptSizes;
    }
}
exports.InputDetail = InputDetail;

},{}],24:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InputSource = void 0;
class InputSource {
    constructor(source) {
        this._source = source;
    }
    selectInputs(target) {
        return this._source(target);
    }
}
exports.InputSource = InputSource;

},{}],25:[function(require,module,exports){
(function (Buffer){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MsgTx = exports.DEFAULT_TICKET_FEE_LIMITS = exports.TX_SERIALIZE_ONLY_WITNESS = exports.TX_SERIALIZE_NO_WITNESS = exports.TX_SERIALIZE_FULL = exports.MIN_TX_PAYLOAD = exports.MAX_TX_OUT_PER_MESSAGE = exports.MIN_TX_OUT_PAYLOAD = exports.MAX_TX_IN_PER_MESSAGE = exports.MIN_TX_IN_PAYLOAD = exports.SEQUENCE_LOCK_TIME_GRANULARITY = exports.SEQUENCE_LOCK_TIME_MASK = exports.SEQUENCE_LOCK_TIME_IS_SECONDS = exports.SEQUENCE_LOCK_TIME_DISABLED = exports.TX_TREE_STAKE = exports.TX_TREE_REGULAR = exports.TX_TREE_UNKNOWN = exports.DEFAULT_PK_SCRIPT_VERSION = exports.NULL_BLOCK_INDEX = exports.NULL_BLOCK_HEIGHT = exports.NULL_VALUE_IN = exports.NO_EXPIRY_VALUE = exports.MAX_PREV_OUT_INDEX = exports.MAX_TX_IN_SEQUENCE_NUM = exports.TX_VERSION = exports.MAX_MESSAGE_PAYLOAD = void 0;
const chainhash = __importStar(require("@demos/chainhash"));
const tx_in_1 = require("./tx_in");
const tx_out_1 = require("./tx_out");
const txsizes_1 = require("@demos/txsizes");
const common_1 = require("./common");
const out_point_1 = require("./out_point");
const utils_1 = require("@demos/utils");
exports.MAX_MESSAGE_PAYLOAD = (1024 * 1024 * 32);
exports.TX_VERSION = 1;
exports.MAX_TX_IN_SEQUENCE_NUM = 0xffffffff;
exports.MAX_PREV_OUT_INDEX = 0xffffffff;
exports.NO_EXPIRY_VALUE = 0;
exports.NULL_VALUE_IN = -1;
exports.NULL_BLOCK_HEIGHT = 0x00000000;
exports.NULL_BLOCK_INDEX = 0xffffffff;
exports.DEFAULT_PK_SCRIPT_VERSION = 0x0000;
exports.TX_TREE_UNKNOWN = -1;
exports.TX_TREE_REGULAR = 0;
exports.TX_TREE_STAKE = 1;
exports.SEQUENCE_LOCK_TIME_DISABLED = 1 << 31;
exports.SEQUENCE_LOCK_TIME_IS_SECONDS = 1 << 22;
exports.SEQUENCE_LOCK_TIME_MASK = 0x0000ffff;
exports.SEQUENCE_LOCK_TIME_GRANULARITY = 9;
exports.MIN_TX_IN_PAYLOAD = 11 + chainhash.Hash.HASH_SIZE;
exports.MAX_TX_IN_PER_MESSAGE = Math.floor((exports.MAX_MESSAGE_PAYLOAD / exports.MIN_TX_IN_PAYLOAD)) + 1;
exports.MIN_TX_OUT_PAYLOAD = 9;
exports.MAX_TX_OUT_PER_MESSAGE = Math.floor((exports.MAX_MESSAGE_PAYLOAD / exports.MIN_TX_OUT_PAYLOAD)) + 1;
exports.MIN_TX_PAYLOAD = 4 + 1 + 1 + 1 + 4 + 4;
exports.TX_SERIALIZE_FULL = 0;
exports.TX_SERIALIZE_NO_WITNESS = 1;
exports.TX_SERIALIZE_ONLY_WITNESS = 2;
exports.DEFAULT_TICKET_FEE_LIMITS = 0x5800;
class MsgTx {
    constructor(cachedHash, serType, version, txIn, txOut, lockTime, expiry) {
        this.cachedHash = cachedHash;
        this.serType = serType || exports.TX_SERIALIZE_FULL;
        this.version = version || exports.TX_VERSION;
        this.txIn = txIn || [];
        this.txOut = txOut || [];
        this.lockTime = lockTime || 0;
        this.expiry = expiry || exports.NO_EXPIRY_VALUE;
    }
    addTxIn(ti) {
        this.txIn.push(ti);
    }
    addTxOut(to) {
        this.txOut.push(to);
    }
    serializeSize() {
        let n = 0;
        switch (this.serType) {
            case exports.TX_SERIALIZE_NO_WITNESS:
                n += 12 +
                    txsizes_1.varIntSerializeSize(this.txIn.length) +
                    txsizes_1.varIntSerializeSize(this.txOut.length);
                for (let i = 0; i < this.txIn.length; i++) {
                    n += this.txIn[i].serializeSizePrefix();
                }
                for (let i = 0; i < this.txOut.length; i++) {
                    n += this.txOut[i].serializeSize();
                }
                break;
            case exports.TX_SERIALIZE_ONLY_WITNESS:
                n += 4 + txsizes_1.varIntSerializeSize(this.txIn.length);
                for (let i = 0; i < this.txIn.length; i++) {
                    n += this.txIn[i].serializeSizeWitness();
                }
                break;
            case exports.TX_SERIALIZE_FULL:
                n += 12 +
                    txsizes_1.varIntSerializeSize(this.txIn.length) +
                    txsizes_1.varIntSerializeSize(this.txIn.length) +
                    txsizes_1.varIntSerializeSize(this.txOut.length);
                for (let i = 0; i < this.txIn.length; i++) {
                    n += this.txIn[i].serializeSizePrefix();
                    n += this.txIn[i].serializeSizeWitness();
                }
                for (let i = 0; i < this.txOut.length; i++) {
                    n += this.txOut[i].serializeSize();
                }
                break;
        }
        return n;
    }
    _decodePrefix(buf, offset = 0) {
        let data = common_1.readVarInt(buf, offset);
        let count = data[0];
        offset = data[1];
        if (count > exports.MAX_TX_IN_PER_MESSAGE) {
            throw new Error(`MsgTx._decodePrefix: too many input transactions to fit into max message size [count ${count}, max ${exports.MAX_TX_IN_PER_MESSAGE}]`);
        }
        this.txIn = new Array(count);
        for (let i = 0; i < count; i++) {
            let ti = new tx_in_1.TxIn();
            this.txIn[i] = ti;
            offset = readTxInPrefix(buf, this.serType, ti, offset);
        }
        data = common_1.readVarInt(buf, offset);
        count = data[0];
        offset = data[1];
        if (count > exports.MAX_TX_OUT_PER_MESSAGE) {
            throw new Error(`MsgTx._decodePrefix: too many output transactions to fit into max message size [count ${count}, max ${exports.MAX_TX_OUT_PER_MESSAGE}]`);
        }
        this.txOut = new Array(count);
        for (let i = 0; i < count; i++) {
            let to = new tx_out_1.TxOut();
            this.txOut[i] = to;
            offset = readTxOut(buf, to, offset);
        }
        this.lockTime = buf.readUInt32LE(offset);
        offset += 4;
        this.expiry = buf.readUInt32LE(offset);
        offset += 4;
        return offset;
    }
    _decodeWitness(buf, offset = 0, isFull = false) {
        if (!isFull) {
            let data = common_1.readVarInt(buf, offset);
            let count = data[0];
            offset = data[1];
            if (count > exports.MAX_TX_IN_PER_MESSAGE) {
                throw new Error(`MsgTx._decodeWitness: too many input transactions to fit into max message size [count ${count}, max ${exports.MAX_TX_IN_PER_MESSAGE}]`);
            }
            this.txIn = new Array(count);
            for (let i = 0; i < count; i++) {
                let ti = new tx_in_1.TxIn();
                this.txIn[i] = ti;
                offset = readTxInWitness(buf, ti, offset);
            }
            this.txOut = new Array(0);
        }
        else {
            let data = common_1.readVarInt(buf, offset);
            let count = data[0];
            offset = data[1];
            if (count != this.txIn.length) {
                throw new Error(`MsgTx._decodeWitness: non equal witness and prefix txin quantities (witness ${count}, prefix ${this.txIn.length})`);
            }
            if (count > exports.MAX_TX_IN_PER_MESSAGE) {
                throw new Error(`MsgTx._decodeWitness: too many input transactions to fit into max message size [count ${count}, max ${exports.MAX_TX_IN_PER_MESSAGE}]`);
            }
            for (let i = 0; i < count; i++) {
                let ti = new tx_in_1.TxIn();
                offset = readTxInWitness(buf, ti, offset);
                this.txIn[i].value = ti.value;
                this.txIn[i].blockHeight = ti.blockHeight;
                this.txIn[i].blockIndex = ti.blockIndex;
                this.txIn[i].signatureScript = ti.signatureScript;
            }
        }
        return offset;
    }
    decode(buf, offset = 0) {
        let ver = buf.readUInt32LE(offset);
        offset += 4;
        this.version = ver & 0xffff;
        this.serType = ver >> 16;
        switch (this.serType) {
            case exports.TX_SERIALIZE_NO_WITNESS:
                offset = this._decodePrefix(buf, offset);
                break;
            case exports.TX_SERIALIZE_ONLY_WITNESS:
                offset = this._decodeWitness(buf, offset, false);
                break;
            case exports.TX_SERIALIZE_FULL:
                offset = this._decodePrefix(buf, offset);
                offset = this._decodeWitness(buf, offset, true);
                break;
            default:
                throw new Error("MsgTx.decode: unsupported transaction type");
        }
    }
    _encodePrefix(buf, offset) {
        let count = this.txIn.length;
        offset = common_1.writeVarInt(buf, count, offset);
        for (let i = 0; i < this.txIn.length; i++) {
            offset = writeTxInPrefix(buf, this.txIn[i], offset);
        }
        count = this.txOut.length;
        offset = common_1.writeVarInt(buf, count, offset);
        for (let i = 0; i < this.txOut.length; i++) {
            offset = writeTxOut(buf, this.txOut[i], offset);
        }
        buf.writeUInt32LE(this.lockTime, offset);
        offset += 4;
        buf.writeUInt32LE(this.expiry, offset);
        offset += 4;
        return offset;
    }
    _encodeWitness(buf, offset) {
        let count = this.txIn.length;
        offset = common_1.writeVarInt(buf, count, offset);
        for (let i = 0; i < this.txIn.length; i++) {
            let ti = this.txIn[i];
            offset = writeTxInWitness(buf, ti, offset);
        }
        return offset;
    }
    encode(buf, offset = 0) {
        let serializedVersion = this.version | this.serType << 16;
        buf.writeUInt32LE(serializedVersion, offset);
        offset += 4;
        switch (this.serType) {
            case exports.TX_SERIALIZE_NO_WITNESS:
                offset = this._encodePrefix(buf, offset);
                break;
            case exports.TX_SERIALIZE_ONLY_WITNESS:
                offset = this._encodeWitness(buf, offset);
                break;
            case exports.TX_SERIALIZE_FULL:
                offset = this._encodePrefix(buf, offset);
                offset = this._encodeWitness(buf, offset);
                break;
            default:
                throw new Error("MsgTx.encode: unsupported transaction type");
        }
    }
    serialize(buf) {
        this.encode(buf, 0);
    }
    deserialize(buf) {
        this.decode(buf, 0);
    }
    _serialize(serType) {
        let txBuf = Buffer.alloc(this.serializeSize());
        this.serialize(txBuf);
        let mtx = MsgTx.fromBytes(txBuf);
        mtx.serType = serType;
        let buf = Buffer.alloc(mtx.serializeSize());
        mtx.serialize(buf);
        return buf;
    }
    _mustSerialize(serType) {
        return this._serialize(serType);
    }
    txHash() {
        let buf = this._mustSerialize(exports.TX_SERIALIZE_NO_WITNESS);
        return chainhash.hashH(buf);
    }
    static fromBytes(buf) {
        let msgTx = new MsgTx();
        msgTx.deserialize(buf);
        return msgTx;
    }
}
exports.MsgTx = MsgTx;
function readScript(buf, maxAllowed, offset, fieldName) {
    let data = common_1.readVarInt(buf, offset);
    let count = data[0];
    offset = data[1];
    if (count > maxAllowed) {
        throw new Error(`${fieldName} is larger than the max allowed size [count ${count}, max ${maxAllowed}]`);
    }
    return [
        buf.slice(offset, offset + count),
        offset + count
    ];
}
function readOutPoint(buf, ti, offset) {
    let hash = buf.slice(offset, offset + chainhash.Hash.HASH_SIZE);
    offset += chainhash.Hash.HASH_SIZE;
    let index = buf.readUInt32LE(offset);
    offset += 4;
    ti.previousOutPoint = new out_point_1.OutPoint(new chainhash.Hash(hash), index, buf.readUInt8(offset));
    offset += 1;
    return offset;
}
function writeOutPoint(buf, op, offset) {
    let hash = op.hash.cloneBytes();
    hash.copy(buf, offset);
    offset += hash.length;
    buf.writeUInt32LE(op.index, offset);
    offset += 4;
    buf.writeUInt32LE(op.tree, offset);
    offset += 1;
    return offset;
}
function readTxInPrefix(buf, serType, ti, offset) {
    if (serType == exports.TX_SERIALIZE_ONLY_WITNESS) {
        throw new Error("readTxInPrefix tried to read a prefix input for a witness only tx");
    }
    offset = readOutPoint(buf, ti, offset);
    ti.sequence = buf.readUInt32BE(offset);
    offset += 4;
    return offset;
}
function readTxInWitness(buf, ti, offset) {
    ti.value = new utils_1.Amount(buf.slice(offset, offset + 8).reverse());
    offset += 8;
    ti.blockHeight = buf.readUInt32BE(offset);
    offset += 4;
    ti.blockIndex = buf.readUInt32BE(offset);
    offset += 4;
    let data = readScript(buf, exports.MAX_MESSAGE_PAYLOAD, offset, "transaction input signature script");
    ti.signatureScript = data[0];
    offset = data[1];
    return offset;
}
function writeTxInPrefix(buf, ti, offset) {
    offset = writeOutPoint(buf, ti.previousOutPoint, offset);
    buf.writeUInt32BE(ti.sequence, offset);
    offset += 4;
    return offset;
}
function writeTxInWitness(buf, ti, offset) {
    ti.value.toBuffer("le", 8).copy(buf, offset);
    offset += 8;
    buf.writeUInt32BE(ti.blockHeight, offset);
    offset += 4;
    buf.writeUInt32BE(ti.blockIndex, offset);
    offset += 4;
    offset = common_1.writeVarBytes(buf, ti.signatureScript, offset);
    return offset;
}
function readTxOut(buf, to, offset) {
    let value = buf.slice(offset, offset + 8).reverse();
    offset += 8;
    to.value = new utils_1.Amount(value);
    to.version = buf.readUInt16BE(offset);
    offset += 2;
    let data = readScript(buf, exports.MAX_MESSAGE_PAYLOAD, offset, "transaction output public key script");
    to.pkScript = data[0];
    offset = data[1];
    return offset;
}
function writeTxOut(buf, to, offset) {
    to.value.toBuffer("le", 8).copy(buf, offset);
    offset += 8;
    buf.writeUInt16BE(to.version, offset);
    offset += 2;
    return common_1.writeVarBytes(buf, to.pkScript, offset);
}

}).call(this,require("buffer").Buffer)
},{"./common":19,"./out_point":26,"./tx_in":30,"./tx_out":31,"@demos/chainhash":4,"@demos/txsizes":45,"@demos/utils":47,"buffer":62}],26:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OutPoint = void 0;
class OutPoint {
    constructor(hash, index, tree) {
        this._hash = hash;
        this._index = index;
        this._tree = tree;
    }
    get hash() {
        return this._hash;
    }
    get index() {
        return this._index;
    }
    get tree() {
        return this._tree;
    }
    toString() {
        return `${this.hash.toString()}:${this.index}:${this.tree}`;
    }
}
exports.OutPoint = OutPoint;

},{}],27:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Store = void 0;
const txsizes = __importStar(require("@demos/txsizes"));
const txscript = __importStar(require("@demos/txscript"));
const utxo_1 = require("./utxo");
const utils_1 = require("@demos/utils");
const tx_in_1 = require("./tx_in");
const input_source_1 = require("./input_source");
const input_detail_1 = require("./input_detail");
const out_point_1 = require("./out_point");
const msg_tx_1 = require("./msg_tx");
class Store {
    constructor() {
        this._utxos = [];
    }
    put(txid, pubKey, vout, amount) {
        this._utxos.push(new utxo_1.Utxo(txid, pubKey, vout, amount));
    }
    makeInputSource() {
        if (!this._utxos.length) {
            throw new Error("Utxo is empty.");
        }
        let currentTotal = new utils_1.Amount(0);
        let currentInputs = [];
        let currentScripts = [];
        let redeemScriptSizes = [];
        return new input_source_1.InputSource((target) => {
            for (let i = 0; i < this._utxos.length; i++) {
                let utxo = this._utxos[i];
                let amt = utxo.amount;
                let pkScript = utxo.pubKey;
                let op = txscript.getP2PKHOpCode(pkScript);
                if (op == txscript.OP_SSTX) {
                    continue;
                }
                let tree = msg_tx_1.TX_TREE_REGULAR;
                if (op != txscript.OP_NOP10) {
                    tree = msg_tx_1.TX_TREE_STAKE;
                }
                let hash = utxo.txid;
                let txIn = new tx_in_1.TxIn(new out_point_1.OutPoint(hash, utxo.vout, tree), msg_tx_1.MAX_TX_IN_SEQUENCE_NUM, utxo.amount, msg_tx_1.NULL_BLOCK_HEIGHT, msg_tx_1.NULL_BLOCK_INDEX);
                let scriptSize = 0;
                let scriptClass = txscript.getScriptClass(txscript.DEFAULT_SCRIPT_VERSION, pkScript);
                switch (scriptClass) {
                    case txscript.PUB_KEY_HASH_TY:
                        scriptSize = txsizes.REDEEM_P2PKH_SIG_SCRIPT_SIZE;
                        break;
                    case txscript.PUB_KEY_TY:
                        scriptSize = txsizes.REDEEM_P2PK_SIG_SCRIPT_SIZE;
                        break;
                    case txscript.STAKE_REVOCATION_TY:
                    case txscript.STAKE_SUB_CHANGE_TY:
                    case txscript.STAKE_GEN_TY:
                        try {
                            scriptClass = txscript.getStakeOutSubclass(pkScript);
                        }
                        catch (e) {
                            throw new Error(`failed to extract nested script in stake output: ${e}`);
                        }
                        if (scriptClass != txscript.PUB_KEY_HASH_TY) {
                            continue;
                        }
                        scriptSize = txsizes.REDEEM_P2PKH_SIG_SCRIPT_SIZE;
                        break;
                    default:
                        continue;
                }
                currentTotal = currentTotal.add(amt);
                redeemScriptSizes.push(scriptSize);
                currentScripts.push(pkScript);
                currentInputs.push(txIn);
            }
            this._utxos.length = 0;
            return new input_detail_1.InputDetail(currentTotal, currentInputs, currentScripts, redeemScriptSizes);
        });
    }
}
exports.Store = Store;

},{"./input_detail":23,"./input_source":24,"./msg_tx":25,"./out_point":26,"./tx_in":30,"./utxo":32,"@demos/txscript":44,"@demos/txsizes":45,"@demos/utils":47}],28:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./common"), exports);
__exportStar(require("./out_point"), exports);
__exportStar(require("./tx_in"), exports);
__exportStar(require("./tx_out"), exports);
__exportStar(require("./helper"), exports);
__exportStar(require("./input_detail"), exports);
__exportStar(require("./input_source"), exports);
__exportStar(require("./store"), exports);
__exportStar(require("./msg_tx"), exports);
__exportStar(require("./authored_tx"), exports);
__exportStar(require("./transaction_destination"), exports);
__exportStar(require("./extended_out_point"), exports);
__exportStar(require("./credit"), exports);

},{"./authored_tx":18,"./common":19,"./credit":20,"./extended_out_point":21,"./helper":22,"./input_detail":23,"./input_source":24,"./msg_tx":25,"./out_point":26,"./store":27,"./transaction_destination":29,"./tx_in":30,"./tx_out":31}],29:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TransactionDestination = void 0;
class TransactionDestination {
    constructor(address, amount) {
        this._address = address;
        this._amount = amount;
    }
    get address() {
        return this._address;
    }
    get amount() {
        return this._amount;
    }
}
exports.TransactionDestination = TransactionDestination;

},{}],30:[function(require,module,exports){
(function (Buffer){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TxIn = void 0;
const chainhash = __importStar(require("@demos/chainhash"));
const utils_1 = require("@demos/utils");
const out_point_1 = require("./out_point");
const txsizes_1 = require("@demos/txsizes");
const msg_tx_1 = require("./msg_tx");
class TxIn {
    constructor(previousOutPoint, sequence, value, blockHeight, blockIndex, signatureScript) {
        this.previousOutPoint = previousOutPoint || new out_point_1.OutPoint(new chainhash.Hash(Buffer.alloc(0)), 0, 0);
        this.sequence = sequence || msg_tx_1.MAX_TX_IN_SEQUENCE_NUM;
        this.value = value || new utils_1.Amount(msg_tx_1.NULL_VALUE_IN);
        this.blockHeight = blockHeight || msg_tx_1.NULL_BLOCK_HEIGHT;
        this.blockIndex = blockIndex || msg_tx_1.NULL_BLOCK_INDEX;
        this.signatureScript = signatureScript || Buffer.alloc(0);
    }
    serializeSizePrefix() {
        return 41;
    }
    serializeSizeWitness() {
        let ssLen = this.signatureScript.length;
        return 8 + 4 + 4 + txsizes_1.varIntSerializeSize(ssLen) + ssLen;
    }
}
exports.TxIn = TxIn;

}).call(this,require("buffer").Buffer)
},{"./msg_tx":25,"./out_point":26,"@demos/chainhash":4,"@demos/txsizes":45,"@demos/utils":47,"buffer":62}],31:[function(require,module,exports){
(function (Buffer){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TxOut = void 0;
const utils_1 = require("@demos/utils");
const txsizes_1 = require("@demos/txsizes");
const msg_tx_1 = require("./msg_tx");
class TxOut {
    constructor(value, version, pkScript) {
        this.value = value || new utils_1.Amount(0);
        this.version = version || msg_tx_1.DEFAULT_PK_SCRIPT_VERSION;
        this.pkScript = pkScript || Buffer.alloc(0);
    }
    serializeSize() {
        let len = this.pkScript.length;
        return 8 + 2 + txsizes_1.varIntSerializeSize(len) + len;
    }
}
exports.TxOut = TxOut;

}).call(this,require("buffer").Buffer)
},{"./msg_tx":25,"@demos/txsizes":45,"@demos/utils":47,"buffer":62}],32:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Utxo = void 0;
class Utxo {
    constructor(txid, pubKey, vout, amount) {
        this._txid = txid;
        this._pubKey = pubKey;
        this._vout = vout;
        this._amount = amount;
    }
    get txid() {
        return this._txid;
    }
    get pubKey() {
        return this._pubKey;
    }
    get vout() {
        return this._vout;
    }
    get amount() {
        return this._amount;
    }
}
exports.Utxo = Utxo;

},{}],33:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.stakePoolTicketFee = exports.feeForSerializeSize = exports.DEFAULT_RELAY_FEE_PER_KB = void 0;
const utils_1 = require("@demos/utils");
const bn_js_1 = __importDefault(require("bn.js"));
exports.DEFAULT_RELAY_FEE_PER_KB = 1e-4;
function feeForSerializeSize(relayFeePerKb, txSerializeSize) {
    let relay = relayFeePerKb.toUnit();
    let fee = Math.floor(relay * txSerializeSize / 1000);
    if (fee === 0 && relay > 0) {
        fee = relay;
    }
    let max = utils_1.MAX_AMOUNT;
    if (fee < 0 || fee > max) {
        fee = max;
    }
    return new utils_1.Amount(fee);
}
exports.feeForSerializeSize = feeForSerializeSize;
function calcBlockSubsidy(height, net) {
    if (height == 1) {
        return net.blockOneSubsidy();
    }
    let iteration = Math.floor(height / net.subsidyReductionInterval);
    if (iteration == 0) {
        return net.baseSubsidy;
    }
    let subsidy = net.baseSubsidy;
    for (let i = 0; i < iteration; i++) {
        subsidy = Math.floor((subsidy * net.mulSubsidy) / net.divSubsidy);
    }
    return subsidy;
}
function calcStakeVoteSubsidy(height, net) {
    let subsidy = calcBlockSubsidy(height, net);
    let proportions = net.totalSubsidyProportions();
    subsidy *= net.stakeRewardProportion;
    subsidy = Math.floor(subsidy / (proportions * net.ticketsPerBlock));
    return subsidy;
}
function stakePoolTicketFee(stakeDiff, relayFee, height, poolFee, net) {
    let poolFeeInt = poolFee * net.mulSubsidy;
    let adjs = Math.ceil(net.ticketPoolSize / net.subsidyReductionInterval);
    let subsidy = calcStakeVoteSubsidy(height, net);
    for (let i = 0; i < adjs; i++) {
        subsidy *= net.mulSubsidy;
        subsidy = Math.floor(subsidy / net.divSubsidy);
    }
    let shift = 64;
    let s = new bn_js_1.default(subsidy);
    let v = new bn_js_1.default(stakeDiff.toUnit());
    let z = new bn_js_1.default(relayFee.toUnit());
    let num = new bn_js_1.default(poolFeeInt);
    num = num.mul(s);
    let vPlusZ = v.clone().add(z);
    num = num.mul(vPlusZ);
    num = num.ushln(shift);
    let den = s.clone();
    den = den.add(v);
    den = den.mul(new bn_js_1.default(1e4));
    num = num.div(den);
    num = num.ushrn(shift);
    return new utils_1.Amount(num.toNumber());
}
exports.stakePoolTicketFee = stakePoolTicketFee;

},{"@demos/utils":47,"bn.js":59}],34:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Engine = exports.SCRIPT_VERIFY_SHA256 = exports.SCRIPT_VERIFY_SIG_PUSH_ONLY = exports.SCRIPT_VERIFY_CLEAN_STACK = exports.SCRIPT_VERIFY_CHECK_SEQUENCE_VERIFY = exports.SCRIPT_VERIFY_CHECK_LOCK_TIME_VERIFY = exports.SCRIPT_DISCOURAGE_UPGRADABLE_NOPS = exports.DEFAULT_SCRIPT_VERSION = exports.MAX_SCRIPT_SIZE = exports.MAX_STACK_SIZE = void 0;
const stack_1 = require("./stack");
const standard_1 = require("./standard");
const script_1 = require("./script");
const opcode_1 = require("./opcode");
exports.MAX_STACK_SIZE = 1024;
exports.MAX_SCRIPT_SIZE = 16384;
exports.DEFAULT_SCRIPT_VERSION = 0;
exports.SCRIPT_DISCOURAGE_UPGRADABLE_NOPS = 1;
exports.SCRIPT_VERIFY_CHECK_LOCK_TIME_VERIFY = 2;
exports.SCRIPT_VERIFY_CHECK_SEQUENCE_VERIFY = 4;
exports.SCRIPT_VERIFY_CLEAN_STACK = 8;
exports.SCRIPT_VERIFY_SIG_PUSH_ONLY = 16;
exports.SCRIPT_VERIFY_SHA256 = 32;
class Engine {
    constructor(scriptPubKey, scriptSig, flags, scriptVersion) {
        // if (txIdx < 0 || txIdx >= tx.txIn.length) {
        //   throw new Error(`transaction input index ${txIdx} is negative or >= ${tx.txIn.length}`);
        // }
        this._bip16 = false;
        this._savedFirstStack = [];
        // let scriptSig = tx.txIn[txIdx].signatureScript;
        if (!scriptSig.length && !scriptPubKey.length) {
            throw new Error("false stack entry at end of script execution");
        }
        this._scriptIdx = 0;
        this._flags = flags;
        this._version = scriptVersion;
        if (this._hasFlag(exports.SCRIPT_VERIFY_SIG_PUSH_ONLY) && !standard_1.isPushOnlyScript(scriptSig)) {
            throw new Error("signature script is not push only");
        }
        if (scriptVersion == exports.DEFAULT_SCRIPT_VERSION) {
            standard_1.hasP2SHScriptSigStakeOpCodes(scriptVersion, scriptSig, scriptPubKey);
        }
        let scripts = [scriptSig, scriptPubKey];
        this._scripts = new Array(scripts.length);
        for (let i = 0; i < scripts.length; i++) {
            let scr = scripts[i];
            if (scr.length > exports.MAX_SCRIPT_SIZE) {
                throw new Error(`script size ${scr.length} is larger than max allowed size ${exports.MAX_SCRIPT_SIZE}`);
            }
            this._scripts[i] = script_1.parseScript(scr);
        }
        if (!scripts[0] || !scripts[0].length) {
            this._scriptIdx++;
        }
        if (standard_1.isAnyKindOfScriptHash(this._scripts[1])) {
            if (standard_1.isPushOnly(this._scripts[0])) {
                throw new Error("pay to script hash is not push only");
            }
            this._bip16 = true;
        }
        this._scriptOff = 0;
        this._dstack = new stack_1.Stack();
        this._astack = new stack_1.Stack();
        this._numOps = 0;
    }
    _hasFlag(flag) {
        return (this._flags & flag) > 0;
    }
    _validPC() {
        var _a, _b;
        if (this._scriptIdx >= this._scripts.length) {
            throw new Error(`past input scripts ${this._scriptIdx}:${this._scriptOff} ${this._scripts.length}:xxxx`);
        }
        if (this._scriptOff >= this._scripts[this._scriptIdx].length) {
            throw new Error(`past input scripts ${this._scriptIdx}:${this._scriptOff} ${this._scriptIdx}:${(_b = (_a = this._scripts[this._scriptIdx]) === null || _a === void 0 ? void 0 : _a.length) !== null && _b !== void 0 ? _b : 0}`);
        }
    }
    _disasm(scriptIdx, scriptOff) {
        return `${scriptIdx}:${scriptOff}:${this._scripts[scriptIdx][scriptOff].print(false)}`;
    }
    _disasmPC() {
        this._validPC();
        return this._disasm(this._scriptIdx, this._scriptOff);
    }
    _isBranchExecuting() {
        return true;
    }
    _executeOpcode(pop) {
        if (pop.isDisabled()) {
            throw new Error(`attempt to execute disabled opcode ${pop.opcode.name}`);
        }
        if (pop.alwaysIllegal()) {
            throw new Error(`attempt to execute reserved opcode ${pop.opcode.name}`);
        }
        if (pop.opcode.value > opcode_1.OP_16) {
            this._numOps++;
            if (this._numOps > script_1.MAX_OPS_PER_SCRIPT) {
                throw new Error(`exceeded max operation limit of ${script_1.MAX_OPS_PER_SCRIPT}`);
            }
        }
        else if (pop.data.length > script_1.MAX_SCRIPT_ELEMENT_SIZE) {
            throw new Error(`element size ${pop.data.length} exceeds max allowed size ${script_1.MAX_SCRIPT_ELEMENT_SIZE}`);
        }
        if (!this._isBranchExecuting() && !pop.isConditional()) {
            return;
        }
        if (this._isBranchExecuting() &&
            pop.opcode.value >= 0 &&
            pop.opcode.value <= opcode_1.OP_PUSHDATA4) {
            pop.checkMinimalDataPush();
        }
    }
    _disasmScript(idx) {
        if (idx >= this._scripts.length) {
            throw new Error(`script index ${idx} >= total scripts ${this._scripts.length}`);
        }
        let disstr = "";
        for (let i = 0; i < this._scripts[idx].length; i++) {
            disstr += this._disasm(idx, i) + '\n';
        }
        return disstr;
    }
    _checkErrorCondition(finalScript) {
        if (this._scriptIdx < this._scripts.length) {
            throw new Error("error check when script unfinished");
        }
        if (finalScript &&
            this._hasFlag(exports.SCRIPT_VERIFY_CLEAN_STACK) &&
            this._dstack.depth() != 1) {
            throw new Error(`stack contains ${this._dstack.depth() - 1} unexpected items`);
        }
        else if (this._dstack.depth() < 1) {
            throw new Error("stack empty at end of script execution");
        }
        let v = this._dstack.popBool();
        if (!v) {
            let dis0, dis1;
            try {
                dis0 = this._disasmScript(0);
            }
            catch (e) {
                dis0 = e.toString();
            }
            try {
                dis1 = this._disasmScript(1);
            }
            catch (e) {
                dis1 = e.toString();
            }
            console.log(`scripts failed:\nscript0: ${dis0}\nscript1: ${dis1}`);
            throw new Error("false stack entry at end of script execution");
        }
    }
    _step() {
        // Verify that it is pointing to a valid script address.
        this._validPC();
        let po = this._scripts[this._scriptIdx][this._scriptOff];
        this._executeOpcode(po);
        let combinedStackSize = this._dstack.depth() + this._astack.depth();
        if (combinedStackSize > exports.MAX_STACK_SIZE) {
            throw new Error(`combined stack size ${combinedStackSize} > max allowed ${exports.MAX_STACK_SIZE}`);
        }
        this._scriptOff++;
        if (this._scriptOff >= this._scripts[this._scriptIdx].length) {
            try {
                this._astack.dropN(this._astack.depth());
            }
            catch (_) {
            }
            this._numOps = 0;
            this._scriptOff = 0;
            if (this._scriptIdx == 0 && this._bip16) {
                this._scriptIdx++;
                this._savedFirstStack = getStack(this._dstack);
            }
            else if (this._scriptIdx == 1 && this._bip16) {
                this._scriptIdx++;
                this._checkErrorCondition(false);
                let script = this._savedFirstStack[this._savedFirstStack.length - 1];
                let pops = script_1.parseScript(script);
                this._scripts.push(pops);
                setStack(this._dstack, this._savedFirstStack);
            }
            else {
                this._scriptIdx++;
            }
            if (this._scriptIdx < this._scripts.length &&
                this._scriptOff >= this._scripts[this._scriptIdx].length) {
                this._scriptIdx++;
            }
            if (this._scriptIdx >= this._scripts.length) {
                return true;
            }
        }
        return false;
    }
    execute() {
        if (this._version != exports.DEFAULT_SCRIPT_VERSION) {
            return "";
        }
        let done = false;
        while (!done) {
            try {
                console.log(`stepping: ${this._disasmPC()}`);
            }
            catch (e) {
                console.log("stepping: ", e);
            }
            done = this._step();
            let dstr, astr;
            if (this._dstack.depth() != 0) {
                dstr = 'Stack:\n' + this._dstack.toString();
            }
            if (this._astack.depth() != 0) {
                astr = 'AltStack:\n' + this._astack.toString();
            }
            return '${dstr}\n${astr}';
        }
        this._checkErrorCondition(true);
        return '';
    }
}
exports.Engine = Engine;
function getStack(stack) {
    let arr = new Array(stack.depth());
    for (let i = 0; i < arr.length; i++) {
        try {
            arr[arr.length - i - 1] = stack.peekByteArray(i);
        }
        catch (_) {
        }
    }
    return arr;
}
function setStack(stack, data) {
    try {
        stack.dropN(stack.depth());
    }
    catch (_) {
    }
    for (let i = 0; i < data.length; i++) {
        stack.pushByteArray(data[i]);
    }
}

},{"./opcode":37,"./script":39,"./stack":42,"./standard":43}],35:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyClosure = void 0;
class KeyClosure {
    constructor(handle) {
        this._getKey = handle;
    }
    getKey(addr) {
        return this._getKey(addr);
    }
}
exports.KeyClosure = KeyClosure;

},{}],36:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpCode = void 0;
class OpCode {
    constructor(value, name, length) {
        this._value = value;
        this._name = name;
        this._length = length;
    }
    get value() {
        return this._value;
    }
    get name() {
        return this._name;
    }
    get length() {
        return this._length;
    }
}
exports.OpCode = OpCode;

},{}],37:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.opcodes = exports.opcodeOnelineRepls = exports.OP_INVALIDOPCODE = exports.OP_PUBKEY = exports.OP_PUBKEYHASH = exports.OP_UNKNOWN252 = exports.OP_PUBKEYS = exports.OP_SMALLINTEGER = exports.OP_INVALID249 = exports.OP_CALL = exports.OP_CREATE = exports.OP_STX = exports.OP_SHA256 = exports.OP_CHECKSIGALTVERIFY = exports.OP_CHECKSIGALT = exports.OP_SSTXCHANGE = exports.OP_SSRTX = exports.OP_SSGEN = exports.OP_SSTX = exports.OP_NOP10 = exports.OP_NOP9 = exports.OP_NOP8 = exports.OP_NOP7 = exports.OP_NOP6 = exports.OP_NOP5 = exports.OP_NOP4 = exports.OP_CHECKSEQUENCEVERIFY = exports.OP_CHECKLOCKTIMEVERIFY = exports.OP_NOP1 = exports.OP_CHECKMULTISIGVERIFY = exports.OP_CHECKMULTISIG = exports.OP_CHECKSIGVERIFY = exports.OP_CHECKSIG = exports.OP_CODESEPARATOR = exports.OP_HASH256 = exports.OP_HASH160 = exports.OP_BLAKE256 = exports.OP_SHA1 = exports.OP_RIPEMD160 = exports.OP_WITHIN = exports.OP_MAX = exports.OP_MIN = exports.OP_GREATERTHANOREQUAL = exports.OP_LESSTHANOREQUAL = exports.OP_GREATERTHAN = exports.OP_LESSTHAN = exports.OP_NUMNOTEQUAL = exports.OP_NUMEQUALVERIFY = exports.OP_NUMEQUAL = exports.OP_BOOLOR = exports.OP_BOOLAND = exports.OP_RSHIFT = exports.OP_LSHIFT = exports.OP_MOD = exports.OP_DIV = exports.OP_MUL = exports.OP_SUB = exports.OP_ADD = exports.OP_0NOTEQUAL = exports.OP_NOT = exports.OP_ABS = exports.OP_NEGATE = exports.OP_2DIV = exports.OP_2MUL = exports.OP_1SUB = exports.OP_1ADD = exports.OP_ROTL = exports.OP_ROTR = exports.OP_EQUALVERIFY = exports.OP_EQUAL = exports.OP_XOR = exports.OP_OR = exports.OP_AND = exports.OP_INVERT = exports.OP_SIZE = exports.OP_RIGHT = exports.OP_LEFT = exports.OP_SUBSTR = exports.OP_CAT = exports.OP_TUCK = exports.OP_SWAP = exports.OP_ROT = exports.OP_ROLL = exports.OP_PICK = exports.OP_OVER = exports.OP_NIP = exports.OP_DUP = exports.OP_DROP = exports.OP_DEPTH = exports.OP_IFDUP = exports.OP_2SWAP = exports.OP_2ROT = exports.OP_2OVER = exports.OP_3DUP = exports.OP_2DUP = exports.OP_2DROP = exports.OP_FROMALTSTACK = exports.OP_TOALTSTACK = exports.OP_RETURN = exports.OP_VERIFY = exports.OP_ENDIF = exports.OP_ELSE = exports.OP_VERNOTIF = exports.OP_VERIF = exports.OP_NOTIF = exports.OP_IF = exports.OP_VER = exports.OP_NOP = exports.OP_16 = exports.OP_15 = exports.OP_14 = exports.OP_13 = exports.OP_12 = exports.OP_11 = exports.OP_10 = exports.OP_9 = exports.OP_8 = exports.OP_7 = exports.OP_6 = exports.OP_5 = exports.OP_4 = exports.OP_3 = exports.OP_2 = exports.OP_TRUE = exports.OP_1 = exports.OP_RESERVED = exports.OP_1NEGATE = exports.OP_PUSHDATA4 = exports.OP_PUSHDATA2 = exports.OP_PUSHDATA1 = exports.OP_DATA_75 = exports.OP_DATA_74 = exports.OP_DATA_73 = exports.OP_DATA_72 = exports.OP_DATA_71 = exports.OP_DATA_70 = exports.OP_DATA_69 = exports.OP_DATA_68 = exports.OP_DATA_67 = exports.OP_DATA_66 = exports.OP_DATA_65 = exports.OP_DATA_64 = exports.OP_DATA_63 = exports.OP_DATA_62 = exports.OP_DATA_61 = exports.OP_DATA_60 = exports.OP_DATA_59 = exports.OP_DATA_58 = exports.OP_DATA_57 = exports.OP_DATA_56 = exports.OP_DATA_55 = exports.OP_DATA_54 = exports.OP_DATA_53 = exports.OP_DATA_52 = exports.OP_DATA_51 = exports.OP_DATA_50 = exports.OP_DATA_49 = exports.OP_DATA_48 = exports.OP_DATA_47 = exports.OP_DATA_46 = exports.OP_DATA_45 = exports.OP_DATA_44 = exports.OP_DATA_43 = exports.OP_DATA_42 = exports.OP_DATA_41 = exports.OP_DATA_40 = exports.OP_DATA_39 = exports.OP_DATA_38 = exports.OP_DATA_37 = exports.OP_DATA_36 = exports.OP_DATA_35 = exports.OP_DATA_34 = exports.OP_DATA_33 = exports.OP_DATA_32 = exports.OP_DATA_31 = exports.OP_DATA_30 = exports.OP_DATA_29 = exports.OP_DATA_28 = exports.OP_DATA_27 = exports.OP_DATA_26 = exports.OP_DATA_25 = exports.OP_DATA_24 = exports.OP_DATA_23 = exports.OP_DATA_22 = exports.OP_DATA_21 = exports.OP_DATA_20 = exports.OP_DATA_19 = exports.OP_DATA_18 = exports.OP_DATA_17 = exports.OP_DATA_16 = exports.OP_DATA_15 = exports.OP_DATA_14 = exports.OP_DATA_13 = exports.OP_DATA_12 = exports.OP_DATA_11 = exports.OP_DATA_10 = exports.OP_DATA_9 = exports.OP_DATA_8 = exports.OP_DATA_7 = exports.OP_DATA_6 = exports.OP_DATA_5 = exports.OP_DATA_4 = exports.OP_DATA_3 = exports.OP_DATA_2 = exports.OP_DATA_1 = exports.OP_FALSE = exports.OP_0 = void 0;
const op_code_1 = require("./op_code");
exports.OP_0 = 0x00;
exports.OP_FALSE = 0x00;
exports.OP_DATA_1 = 0x01;
exports.OP_DATA_2 = 0x02;
exports.OP_DATA_3 = 0x03;
exports.OP_DATA_4 = 0x04;
exports.OP_DATA_5 = 0x05;
exports.OP_DATA_6 = 0x06;
exports.OP_DATA_7 = 0x07;
exports.OP_DATA_8 = 0x08;
exports.OP_DATA_9 = 0x09;
exports.OP_DATA_10 = 0x0a;
exports.OP_DATA_11 = 0x0b;
exports.OP_DATA_12 = 0x0c;
exports.OP_DATA_13 = 0x0d;
exports.OP_DATA_14 = 0x0e;
exports.OP_DATA_15 = 0x0f;
exports.OP_DATA_16 = 0x10;
exports.OP_DATA_17 = 0x11;
exports.OP_DATA_18 = 0x12;
exports.OP_DATA_19 = 0x13;
exports.OP_DATA_20 = 0x14;
exports.OP_DATA_21 = 0x15;
exports.OP_DATA_22 = 0x16;
exports.OP_DATA_23 = 0x17;
exports.OP_DATA_24 = 0x18;
exports.OP_DATA_25 = 0x19;
exports.OP_DATA_26 = 0x1a;
exports.OP_DATA_27 = 0x1b;
exports.OP_DATA_28 = 0x1c;
exports.OP_DATA_29 = 0x1d;
exports.OP_DATA_30 = 0x1e;
exports.OP_DATA_31 = 0x1f;
exports.OP_DATA_32 = 0x20;
exports.OP_DATA_33 = 0x21;
exports.OP_DATA_34 = 0x22;
exports.OP_DATA_35 = 0x23;
exports.OP_DATA_36 = 0x24;
exports.OP_DATA_37 = 0x25;
exports.OP_DATA_38 = 0x26;
exports.OP_DATA_39 = 0x27;
exports.OP_DATA_40 = 0x28;
exports.OP_DATA_41 = 0x29;
exports.OP_DATA_42 = 0x2a;
exports.OP_DATA_43 = 0x2b;
exports.OP_DATA_44 = 0x2c;
exports.OP_DATA_45 = 0x2d;
exports.OP_DATA_46 = 0x2e;
exports.OP_DATA_47 = 0x2f;
exports.OP_DATA_48 = 0x30;
exports.OP_DATA_49 = 0x31;
exports.OP_DATA_50 = 0x32;
exports.OP_DATA_51 = 0x33;
exports.OP_DATA_52 = 0x34;
exports.OP_DATA_53 = 0x35;
exports.OP_DATA_54 = 0x36;
exports.OP_DATA_55 = 0x37;
exports.OP_DATA_56 = 0x38;
exports.OP_DATA_57 = 0x39;
exports.OP_DATA_58 = 0x3a;
exports.OP_DATA_59 = 0x3b;
exports.OP_DATA_60 = 0x3c;
exports.OP_DATA_61 = 0x3d;
exports.OP_DATA_62 = 0x3e;
exports.OP_DATA_63 = 0x3f;
exports.OP_DATA_64 = 0x40;
exports.OP_DATA_65 = 0x41;
exports.OP_DATA_66 = 0x42;
exports.OP_DATA_67 = 0x43;
exports.OP_DATA_68 = 0x44;
exports.OP_DATA_69 = 0x45;
exports.OP_DATA_70 = 0x46;
exports.OP_DATA_71 = 0x47;
exports.OP_DATA_72 = 0x48;
exports.OP_DATA_73 = 0x49;
exports.OP_DATA_74 = 0x4a;
exports.OP_DATA_75 = 0x4b;
exports.OP_PUSHDATA1 = 0x4c;
exports.OP_PUSHDATA2 = 0x4d;
exports.OP_PUSHDATA4 = 0x4e;
exports.OP_1NEGATE = 0x4f;
exports.OP_RESERVED = 0x50;
exports.OP_1 = 0x51;
exports.OP_TRUE = 0x51;
exports.OP_2 = 0x52;
exports.OP_3 = 0x53;
exports.OP_4 = 0x54;
exports.OP_5 = 0x55;
exports.OP_6 = 0x56;
exports.OP_7 = 0x57;
exports.OP_8 = 0x58;
exports.OP_9 = 0x59;
exports.OP_10 = 0x5a;
exports.OP_11 = 0x5b;
exports.OP_12 = 0x5c;
exports.OP_13 = 0x5d;
exports.OP_14 = 0x5e;
exports.OP_15 = 0x5f;
exports.OP_16 = 0x60;
exports.OP_NOP = 0x61;
exports.OP_VER = 0x62;
exports.OP_IF = 0x63;
exports.OP_NOTIF = 0x64;
exports.OP_VERIF = 0x65;
exports.OP_VERNOTIF = 0x66;
exports.OP_ELSE = 0x67;
exports.OP_ENDIF = 0x68;
exports.OP_VERIFY = 0x69;
exports.OP_RETURN = 0x6a;
exports.OP_TOALTSTACK = 0x6b;
exports.OP_FROMALTSTACK = 0x6c;
exports.OP_2DROP = 0x6d;
exports.OP_2DUP = 0x6e;
exports.OP_3DUP = 0x6f;
exports.OP_2OVER = 0x70;
exports.OP_2ROT = 0x71;
exports.OP_2SWAP = 0x72;
exports.OP_IFDUP = 0x73;
exports.OP_DEPTH = 0x74;
exports.OP_DROP = 0x75;
exports.OP_DUP = 0x76;
exports.OP_NIP = 0x77;
exports.OP_OVER = 0x78;
exports.OP_PICK = 0x79;
exports.OP_ROLL = 0x7a;
exports.OP_ROT = 0x7b;
exports.OP_SWAP = 0x7c;
exports.OP_TUCK = 0x7d;
exports.OP_CAT = 0x7e;
exports.OP_SUBSTR = 0x7f;
exports.OP_LEFT = 0x80;
exports.OP_RIGHT = 0x81;
exports.OP_SIZE = 0x82;
exports.OP_INVERT = 0x83;
exports.OP_AND = 0x84;
exports.OP_OR = 0x85;
exports.OP_XOR = 0x86;
exports.OP_EQUAL = 0x87;
exports.OP_EQUALVERIFY = 0x88;
exports.OP_ROTR = 0x89;
exports.OP_ROTL = 0x8a;
exports.OP_1ADD = 0x8b;
exports.OP_1SUB = 0x8c;
exports.OP_2MUL = 0x8d;
exports.OP_2DIV = 0x8e;
exports.OP_NEGATE = 0x8f;
exports.OP_ABS = 0x90;
exports.OP_NOT = 0x91;
exports.OP_0NOTEQUAL = 0x92;
exports.OP_ADD = 0x93;
exports.OP_SUB = 0x94;
exports.OP_MUL = 0x95;
exports.OP_DIV = 0x96;
exports.OP_MOD = 0x97;
exports.OP_LSHIFT = 0x98;
exports.OP_RSHIFT = 0x99;
exports.OP_BOOLAND = 0x9a;
exports.OP_BOOLOR = 0x9b;
exports.OP_NUMEQUAL = 0x9c;
exports.OP_NUMEQUALVERIFY = 0x9d;
exports.OP_NUMNOTEQUAL = 0x9e;
exports.OP_LESSTHAN = 0x9f;
exports.OP_GREATERTHAN = 0xa0;
exports.OP_LESSTHANOREQUAL = 0xa1;
exports.OP_GREATERTHANOREQUAL = 0xa2;
exports.OP_MIN = 0xa3;
exports.OP_MAX = 0xa4;
exports.OP_WITHIN = 0xa5;
exports.OP_RIPEMD160 = 0xa6;
exports.OP_SHA1 = 0xa7;
exports.OP_BLAKE256 = 0xa8;
exports.OP_HASH160 = 0xa9;
exports.OP_HASH256 = 0xaa;
exports.OP_CODESEPARATOR = 0xab;
exports.OP_CHECKSIG = 0xac;
exports.OP_CHECKSIGVERIFY = 0xad;
exports.OP_CHECKMULTISIG = 0xae;
exports.OP_CHECKMULTISIGVERIFY = 0xaf;
exports.OP_NOP1 = 0xb0;
exports.OP_CHECKLOCKTIMEVERIFY = 0xb1;
exports.OP_CHECKSEQUENCEVERIFY = 0xb2;
exports.OP_NOP4 = 0xb3;
exports.OP_NOP5 = 0xb4;
exports.OP_NOP6 = 0xb5;
exports.OP_NOP7 = 0xb6;
exports.OP_NOP8 = 0xb7;
exports.OP_NOP9 = 0xb8;
exports.OP_NOP10 = 0xb9;
exports.OP_SSTX = 0xba;
exports.OP_SSGEN = 0xbb;
exports.OP_SSRTX = 0xbc;
exports.OP_SSTXCHANGE = 0xbd;
exports.OP_CHECKSIGALT = 0xbe;
exports.OP_CHECKSIGALTVERIFY = 0xbf;
exports.OP_SHA256 = 0xc0;
exports.OP_STX = 0xc1;
exports.OP_CREATE = 0xc2;
exports.OP_CALL = 0xc3;
exports.OP_INVALID249 = 0xf9;
exports.OP_SMALLINTEGER = 0xfa;
exports.OP_PUBKEYS = 0xfb;
exports.OP_UNKNOWN252 = 0xfc;
exports.OP_PUBKEYHASH = 0xfd;
exports.OP_PUBKEY = 0xfe;
exports.OP_INVALIDOPCODE = 0xff;
exports.opcodeOnelineRepls = new Map();
exports.opcodeOnelineRepls.set("OP_1NEGATE", "-1");
exports.opcodeOnelineRepls.set("OP_0", "0");
exports.opcodeOnelineRepls.set("OP_1", "1");
exports.opcodeOnelineRepls.set("OP_2", "2");
exports.opcodeOnelineRepls.set("OP_3", "3");
exports.opcodeOnelineRepls.set("OP_4", "4");
exports.opcodeOnelineRepls.set("OP_5", "5");
exports.opcodeOnelineRepls.set("OP_6", "6");
exports.opcodeOnelineRepls.set("OP_7", "7");
exports.opcodeOnelineRepls.set("OP_8", "8");
exports.opcodeOnelineRepls.set("OP_9", "9");
exports.opcodeOnelineRepls.set("OP_10", "10");
exports.opcodeOnelineRepls.set("OP_11", "11");
exports.opcodeOnelineRepls.set("OP_12", "12");
exports.opcodeOnelineRepls.set("OP_13", "13");
exports.opcodeOnelineRepls.set("OP_14", "14");
exports.opcodeOnelineRepls.set("OP_15", "15");
exports.opcodeOnelineRepls.set("OP_16", "16");
exports.opcodes = new Map();
exports.opcodes.set(exports.OP_FALSE, new op_code_1.OpCode(exports.OP_FALSE, 'OP_0', 1));
exports.opcodes.set(exports.OP_DATA_1, new op_code_1.OpCode(exports.OP_DATA_1, 'OP_DATA_1', 2));
exports.opcodes.set(exports.OP_DATA_2, new op_code_1.OpCode(exports.OP_DATA_2, 'OP_DATA_2', 3));
exports.opcodes.set(exports.OP_DATA_3, new op_code_1.OpCode(exports.OP_DATA_3, 'OP_DATA_3', 4));
exports.opcodes.set(exports.OP_DATA_4, new op_code_1.OpCode(exports.OP_DATA_4, 'OP_DATA_4', 5));
exports.opcodes.set(exports.OP_DATA_5, new op_code_1.OpCode(exports.OP_DATA_5, 'OP_DATA_5', 6));
exports.opcodes.set(exports.OP_DATA_6, new op_code_1.OpCode(exports.OP_DATA_6, 'OP_DATA_6', 7));
exports.opcodes.set(exports.OP_DATA_7, new op_code_1.OpCode(exports.OP_DATA_7, 'OP_DATA_7', 8));
exports.opcodes.set(exports.OP_DATA_8, new op_code_1.OpCode(exports.OP_DATA_8, 'OP_DATA_8', 9));
exports.opcodes.set(exports.OP_DATA_9, new op_code_1.OpCode(exports.OP_DATA_9, 'OP_DATA_9', 10));
exports.opcodes.set(exports.OP_DATA_10, new op_code_1.OpCode(exports.OP_DATA_10, 'OP_DATA_10', 11));
exports.opcodes.set(exports.OP_DATA_11, new op_code_1.OpCode(exports.OP_DATA_11, 'OP_DATA_11', 12));
exports.opcodes.set(exports.OP_DATA_12, new op_code_1.OpCode(exports.OP_DATA_12, 'OP_DATA_12', 13));
exports.opcodes.set(exports.OP_DATA_13, new op_code_1.OpCode(exports.OP_DATA_13, 'OP_DATA_13', 14));
exports.opcodes.set(exports.OP_DATA_14, new op_code_1.OpCode(exports.OP_DATA_14, 'OP_DATA_14', 15));
exports.opcodes.set(exports.OP_DATA_15, new op_code_1.OpCode(exports.OP_DATA_15, 'OP_DATA_15', 16));
exports.opcodes.set(exports.OP_DATA_16, new op_code_1.OpCode(exports.OP_DATA_16, 'OP_DATA_16', 17));
exports.opcodes.set(exports.OP_DATA_17, new op_code_1.OpCode(exports.OP_DATA_17, 'OP_DATA_17', 18));
exports.opcodes.set(exports.OP_DATA_18, new op_code_1.OpCode(exports.OP_DATA_18, 'OP_DATA_18', 19));
exports.opcodes.set(exports.OP_DATA_19, new op_code_1.OpCode(exports.OP_DATA_19, 'OP_DATA_19', 20));
exports.opcodes.set(exports.OP_DATA_20, new op_code_1.OpCode(exports.OP_DATA_20, 'OP_DATA_20', 21));
exports.opcodes.set(exports.OP_DATA_21, new op_code_1.OpCode(exports.OP_DATA_21, 'OP_DATA_21', 22));
exports.opcodes.set(exports.OP_DATA_22, new op_code_1.OpCode(exports.OP_DATA_22, 'OP_DATA_22', 23));
exports.opcodes.set(exports.OP_DATA_23, new op_code_1.OpCode(exports.OP_DATA_23, 'OP_DATA_23', 24));
exports.opcodes.set(exports.OP_DATA_24, new op_code_1.OpCode(exports.OP_DATA_24, 'OP_DATA_24', 25));
exports.opcodes.set(exports.OP_DATA_25, new op_code_1.OpCode(exports.OP_DATA_25, 'OP_DATA_25', 26));
exports.opcodes.set(exports.OP_DATA_26, new op_code_1.OpCode(exports.OP_DATA_26, 'OP_DATA_26', 27));
exports.opcodes.set(exports.OP_DATA_27, new op_code_1.OpCode(exports.OP_DATA_27, 'OP_DATA_27', 28));
exports.opcodes.set(exports.OP_DATA_28, new op_code_1.OpCode(exports.OP_DATA_28, 'OP_DATA_28', 29));
exports.opcodes.set(exports.OP_DATA_29, new op_code_1.OpCode(exports.OP_DATA_29, 'OP_DATA_29', 30));
exports.opcodes.set(exports.OP_DATA_30, new op_code_1.OpCode(exports.OP_DATA_30, 'OP_DATA_30', 31));
exports.opcodes.set(exports.OP_DATA_31, new op_code_1.OpCode(exports.OP_DATA_31, 'OP_DATA_31', 32));
exports.opcodes.set(exports.OP_DATA_32, new op_code_1.OpCode(exports.OP_DATA_32, 'OP_DATA_32', 33));
exports.opcodes.set(exports.OP_DATA_33, new op_code_1.OpCode(exports.OP_DATA_33, 'OP_DATA_33', 34));
exports.opcodes.set(exports.OP_DATA_34, new op_code_1.OpCode(exports.OP_DATA_34, 'OP_DATA_34', 35));
exports.opcodes.set(exports.OP_DATA_35, new op_code_1.OpCode(exports.OP_DATA_35, 'OP_DATA_35', 36));
exports.opcodes.set(exports.OP_DATA_36, new op_code_1.OpCode(exports.OP_DATA_36, 'OP_DATA_36', 37));
exports.opcodes.set(exports.OP_DATA_37, new op_code_1.OpCode(exports.OP_DATA_37, 'OP_DATA_37', 38));
exports.opcodes.set(exports.OP_DATA_38, new op_code_1.OpCode(exports.OP_DATA_38, 'OP_DATA_38', 39));
exports.opcodes.set(exports.OP_DATA_39, new op_code_1.OpCode(exports.OP_DATA_39, 'OP_DATA_39', 40));
exports.opcodes.set(exports.OP_DATA_40, new op_code_1.OpCode(exports.OP_DATA_40, 'OP_DATA_40', 41));
exports.opcodes.set(exports.OP_DATA_41, new op_code_1.OpCode(exports.OP_DATA_41, 'OP_DATA_41', 42));
exports.opcodes.set(exports.OP_DATA_42, new op_code_1.OpCode(exports.OP_DATA_42, 'OP_DATA_42', 43));
exports.opcodes.set(exports.OP_DATA_43, new op_code_1.OpCode(exports.OP_DATA_43, 'OP_DATA_43', 44));
exports.opcodes.set(exports.OP_DATA_44, new op_code_1.OpCode(exports.OP_DATA_44, 'OP_DATA_44', 45));
exports.opcodes.set(exports.OP_DATA_45, new op_code_1.OpCode(exports.OP_DATA_45, 'OP_DATA_45', 46));
exports.opcodes.set(exports.OP_DATA_46, new op_code_1.OpCode(exports.OP_DATA_46, 'OP_DATA_46', 47));
exports.opcodes.set(exports.OP_DATA_47, new op_code_1.OpCode(exports.OP_DATA_47, 'OP_DATA_47', 48));
exports.opcodes.set(exports.OP_DATA_48, new op_code_1.OpCode(exports.OP_DATA_48, 'OP_DATA_48', 49));
exports.opcodes.set(exports.OP_DATA_49, new op_code_1.OpCode(exports.OP_DATA_49, 'OP_DATA_49', 50));
exports.opcodes.set(exports.OP_DATA_50, new op_code_1.OpCode(exports.OP_DATA_50, 'OP_DATA_50', 51));
exports.opcodes.set(exports.OP_DATA_51, new op_code_1.OpCode(exports.OP_DATA_51, 'OP_DATA_51', 52));
exports.opcodes.set(exports.OP_DATA_52, new op_code_1.OpCode(exports.OP_DATA_52, 'OP_DATA_52', 53));
exports.opcodes.set(exports.OP_DATA_53, new op_code_1.OpCode(exports.OP_DATA_53, 'OP_DATA_53', 54));
exports.opcodes.set(exports.OP_DATA_54, new op_code_1.OpCode(exports.OP_DATA_54, 'OP_DATA_54', 55));
exports.opcodes.set(exports.OP_DATA_55, new op_code_1.OpCode(exports.OP_DATA_55, 'OP_DATA_55', 56));
exports.opcodes.set(exports.OP_DATA_56, new op_code_1.OpCode(exports.OP_DATA_56, 'OP_DATA_56', 57));
exports.opcodes.set(exports.OP_DATA_57, new op_code_1.OpCode(exports.OP_DATA_57, 'OP_DATA_57', 58));
exports.opcodes.set(exports.OP_DATA_58, new op_code_1.OpCode(exports.OP_DATA_58, 'OP_DATA_58', 59));
exports.opcodes.set(exports.OP_DATA_59, new op_code_1.OpCode(exports.OP_DATA_59, 'OP_DATA_59', 60));
exports.opcodes.set(exports.OP_DATA_60, new op_code_1.OpCode(exports.OP_DATA_60, 'OP_DATA_60', 61));
exports.opcodes.set(exports.OP_DATA_61, new op_code_1.OpCode(exports.OP_DATA_61, 'OP_DATA_61', 62));
exports.opcodes.set(exports.OP_DATA_62, new op_code_1.OpCode(exports.OP_DATA_62, 'OP_DATA_62', 63));
exports.opcodes.set(exports.OP_DATA_63, new op_code_1.OpCode(exports.OP_DATA_63, 'OP_DATA_63', 64));
exports.opcodes.set(exports.OP_DATA_64, new op_code_1.OpCode(exports.OP_DATA_64, 'OP_DATA_64', 65));
exports.opcodes.set(exports.OP_DATA_65, new op_code_1.OpCode(exports.OP_DATA_65, 'OP_DATA_65', 66));
exports.opcodes.set(exports.OP_DATA_66, new op_code_1.OpCode(exports.OP_DATA_66, 'OP_DATA_66', 67));
exports.opcodes.set(exports.OP_DATA_67, new op_code_1.OpCode(exports.OP_DATA_67, 'OP_DATA_67', 68));
exports.opcodes.set(exports.OP_DATA_68, new op_code_1.OpCode(exports.OP_DATA_68, 'OP_DATA_68', 69));
exports.opcodes.set(exports.OP_DATA_69, new op_code_1.OpCode(exports.OP_DATA_69, 'OP_DATA_69', 70));
exports.opcodes.set(exports.OP_DATA_70, new op_code_1.OpCode(exports.OP_DATA_70, 'OP_DATA_70', 71));
exports.opcodes.set(exports.OP_DATA_71, new op_code_1.OpCode(exports.OP_DATA_71, 'OP_DATA_71', 72));
exports.opcodes.set(exports.OP_DATA_72, new op_code_1.OpCode(exports.OP_DATA_72, 'OP_DATA_72', 73));
exports.opcodes.set(exports.OP_DATA_73, new op_code_1.OpCode(exports.OP_DATA_73, 'OP_DATA_73', 74));
exports.opcodes.set(exports.OP_DATA_74, new op_code_1.OpCode(exports.OP_DATA_74, 'OP_DATA_74', 75));
exports.opcodes.set(exports.OP_DATA_75, new op_code_1.OpCode(exports.OP_DATA_75, 'OP_DATA_75', 76));
exports.opcodes.set(exports.OP_PUSHDATA1, new op_code_1.OpCode(exports.OP_PUSHDATA1, 'OP_PUSHDATA1', -1));
exports.opcodes.set(exports.OP_PUSHDATA2, new op_code_1.OpCode(exports.OP_PUSHDATA2, 'OP_PUSHDATA2', -2));
exports.opcodes.set(exports.OP_PUSHDATA4, new op_code_1.OpCode(exports.OP_PUSHDATA4, 'OP_PUSHDATA4', -4));
exports.opcodes.set(exports.OP_1NEGATE, new op_code_1.OpCode(exports.OP_1NEGATE, 'OP_1NEGATE', 1));
exports.opcodes.set(exports.OP_RESERVED, new op_code_1.OpCode(exports.OP_RESERVED, 'OP_RESERVED', 1));
exports.opcodes.set(exports.OP_TRUE, new op_code_1.OpCode(exports.OP_TRUE, 'OP_1', 1));
exports.opcodes.set(exports.OP_2, new op_code_1.OpCode(exports.OP_2, 'OP_2', 1));
exports.opcodes.set(exports.OP_3, new op_code_1.OpCode(exports.OP_3, 'OP_3', 1));
exports.opcodes.set(exports.OP_4, new op_code_1.OpCode(exports.OP_4, 'OP_4', 1));
exports.opcodes.set(exports.OP_5, new op_code_1.OpCode(exports.OP_5, 'OP_5', 1));
exports.opcodes.set(exports.OP_6, new op_code_1.OpCode(exports.OP_6, 'OP_6', 1));
exports.opcodes.set(exports.OP_7, new op_code_1.OpCode(exports.OP_7, 'OP_7', 1));
exports.opcodes.set(exports.OP_8, new op_code_1.OpCode(exports.OP_8, 'OP_8', 1));
exports.opcodes.set(exports.OP_9, new op_code_1.OpCode(exports.OP_9, 'OP_9', 1));
exports.opcodes.set(exports.OP_10, new op_code_1.OpCode(exports.OP_10, 'OP_10', 1));
exports.opcodes.set(exports.OP_11, new op_code_1.OpCode(exports.OP_11, 'OP_11', 1));
exports.opcodes.set(exports.OP_12, new op_code_1.OpCode(exports.OP_12, 'OP_12', 1));
exports.opcodes.set(exports.OP_13, new op_code_1.OpCode(exports.OP_13, 'OP_13', 1));
exports.opcodes.set(exports.OP_14, new op_code_1.OpCode(exports.OP_14, 'OP_14', 1));
exports.opcodes.set(exports.OP_15, new op_code_1.OpCode(exports.OP_15, 'OP_15', 1));
exports.opcodes.set(exports.OP_16, new op_code_1.OpCode(exports.OP_16, 'OP_16', 1));
exports.opcodes.set(exports.OP_NOP, new op_code_1.OpCode(exports.OP_NOP, 'OP_NOP', 1));
exports.opcodes.set(exports.OP_VER, new op_code_1.OpCode(exports.OP_VER, 'OP_VER', 1));
exports.opcodes.set(exports.OP_IF, new op_code_1.OpCode(exports.OP_IF, 'OP_IF', 1));
exports.opcodes.set(exports.OP_NOTIF, new op_code_1.OpCode(exports.OP_NOTIF, 'OP_NOTIF', 1));
exports.opcodes.set(exports.OP_VERIF, new op_code_1.OpCode(exports.OP_VERIF, 'OP_VERIF', 1));
exports.opcodes.set(exports.OP_VERNOTIF, new op_code_1.OpCode(exports.OP_VERNOTIF, 'OP_VERNOTIF', 1));
exports.opcodes.set(exports.OP_ELSE, new op_code_1.OpCode(exports.OP_ELSE, 'OP_ELSE', 1));
exports.opcodes.set(exports.OP_ENDIF, new op_code_1.OpCode(exports.OP_ENDIF, 'OP_ENDIF', 1));
exports.opcodes.set(exports.OP_VERIFY, new op_code_1.OpCode(exports.OP_VERIFY, 'OP_VERIFY', 1));
exports.opcodes.set(exports.OP_RETURN, new op_code_1.OpCode(exports.OP_RETURN, 'OP_RETURN', 1));
exports.opcodes.set(exports.OP_CHECKLOCKTIMEVERIFY, new op_code_1.OpCode(exports.OP_CHECKLOCKTIMEVERIFY, 'OP_CHECKLOCKTIMEVERIFY', 1));
exports.opcodes.set(exports.OP_CHECKSEQUENCEVERIFY, new op_code_1.OpCode(exports.OP_CHECKSEQUENCEVERIFY, 'OP_CHECKSEQUENCEVERIFY', 1));
exports.opcodes.set(exports.OP_TOALTSTACK, new op_code_1.OpCode(exports.OP_TOALTSTACK, 'OP_TOALTSTACK', 1));
exports.opcodes.set(exports.OP_FROMALTSTACK, new op_code_1.OpCode(exports.OP_FROMALTSTACK, 'OP_FROMALTSTACK', 1));
exports.opcodes.set(exports.OP_2DROP, new op_code_1.OpCode(exports.OP_2DROP, 'OP_2DROP', 1));
exports.opcodes.set(exports.OP_2DUP, new op_code_1.OpCode(exports.OP_2DUP, 'OP_2DUP', 1));
exports.opcodes.set(exports.OP_3DUP, new op_code_1.OpCode(exports.OP_3DUP, 'OP_3DUP', 1));
exports.opcodes.set(exports.OP_2OVER, new op_code_1.OpCode(exports.OP_2OVER, 'OP_2OVER', 1));
exports.opcodes.set(exports.OP_2ROT, new op_code_1.OpCode(exports.OP_2ROT, 'OP_2ROT', 1));
exports.opcodes.set(exports.OP_2SWAP, new op_code_1.OpCode(exports.OP_2SWAP, 'OP_2SWAP', 1));
exports.opcodes.set(exports.OP_IFDUP, new op_code_1.OpCode(exports.OP_IFDUP, 'OP_IFDUP', 1));
exports.opcodes.set(exports.OP_DEPTH, new op_code_1.OpCode(exports.OP_DEPTH, 'OP_DEPTH', 1));
exports.opcodes.set(exports.OP_DROP, new op_code_1.OpCode(exports.OP_DROP, 'OP_DROP', 1));
exports.opcodes.set(exports.OP_DUP, new op_code_1.OpCode(exports.OP_DUP, 'OP_DUP', 1));
exports.opcodes.set(exports.OP_NIP, new op_code_1.OpCode(exports.OP_NIP, 'OP_NIP', 1));
exports.opcodes.set(exports.OP_OVER, new op_code_1.OpCode(exports.OP_OVER, 'OP_OVER', 1));
exports.opcodes.set(exports.OP_PICK, new op_code_1.OpCode(exports.OP_PICK, 'OP_PICK', 1));
exports.opcodes.set(exports.OP_ROLL, new op_code_1.OpCode(exports.OP_ROLL, 'OP_ROLL', 1));
exports.opcodes.set(exports.OP_ROT, new op_code_1.OpCode(exports.OP_ROT, 'OP_ROT', 1));
exports.opcodes.set(exports.OP_SWAP, new op_code_1.OpCode(exports.OP_SWAP, 'OP_SWAP', 1));
exports.opcodes.set(exports.OP_TUCK, new op_code_1.OpCode(exports.OP_TUCK, 'OP_TUCK', 1));
exports.opcodes.set(exports.OP_CAT, new op_code_1.OpCode(exports.OP_CAT, 'OP_CAT', 1));
exports.opcodes.set(exports.OP_SUBSTR, new op_code_1.OpCode(exports.OP_SUBSTR, 'OP_SUBSTR', 1));
exports.opcodes.set(exports.OP_LEFT, new op_code_1.OpCode(exports.OP_LEFT, 'OP_LEFT', 1));
exports.opcodes.set(exports.OP_RIGHT, new op_code_1.OpCode(exports.OP_RIGHT, 'OP_RIGHT', 1));
exports.opcodes.set(exports.OP_SIZE, new op_code_1.OpCode(exports.OP_SIZE, 'OP_SIZE', 1));
exports.opcodes.set(exports.OP_INVERT, new op_code_1.OpCode(exports.OP_INVERT, 'OP_INVERT', 1));
exports.opcodes.set(exports.OP_AND, new op_code_1.OpCode(exports.OP_AND, 'OP_AND', 1));
exports.opcodes.set(exports.OP_OR, new op_code_1.OpCode(exports.OP_OR, 'OP_OR', 1));
exports.opcodes.set(exports.OP_XOR, new op_code_1.OpCode(exports.OP_XOR, 'OP_XOR', 1));
exports.opcodes.set(exports.OP_EQUAL, new op_code_1.OpCode(exports.OP_EQUAL, 'OP_EQUAL', 1));
exports.opcodes.set(exports.OP_EQUALVERIFY, new op_code_1.OpCode(exports.OP_EQUALVERIFY, 'OP_EQUALVERIFY', 1));
exports.opcodes.set(exports.OP_ROTR, new op_code_1.OpCode(exports.OP_ROTR, 'OP_ROTR', 1));
exports.opcodes.set(exports.OP_ROTL, new op_code_1.OpCode(exports.OP_ROTL, 'OP_ROTL', 1));
exports.opcodes.set(exports.OP_1ADD, new op_code_1.OpCode(exports.OP_1ADD, 'OP_1ADD', 1));
exports.opcodes.set(exports.OP_1SUB, new op_code_1.OpCode(exports.OP_1SUB, 'OP_1SUB', 1));
exports.opcodes.set(exports.OP_2MUL, new op_code_1.OpCode(exports.OP_2MUL, 'OP_2MUL', 1));
exports.opcodes.set(exports.OP_2DIV, new op_code_1.OpCode(exports.OP_2DIV, 'OP_2DIV', 1));
exports.opcodes.set(exports.OP_NEGATE, new op_code_1.OpCode(exports.OP_NEGATE, 'OP_NEGATE', 1));
exports.opcodes.set(exports.OP_ABS, new op_code_1.OpCode(exports.OP_ABS, 'OP_ABS', 1));
exports.opcodes.set(exports.OP_NOT, new op_code_1.OpCode(exports.OP_NOT, 'OP_NOT', 1));
exports.opcodes.set(exports.OP_0NOTEQUAL, new op_code_1.OpCode(exports.OP_0NOTEQUAL, 'OP_0NOTEQUAL', 1));
exports.opcodes.set(exports.OP_ADD, new op_code_1.OpCode(exports.OP_ADD, 'OP_ADD', 1));
exports.opcodes.set(exports.OP_SUB, new op_code_1.OpCode(exports.OP_SUB, 'OP_SUB', 1));
exports.opcodes.set(exports.OP_MUL, new op_code_1.OpCode(exports.OP_MUL, 'OP_MUL', 1));
exports.opcodes.set(exports.OP_DIV, new op_code_1.OpCode(exports.OP_DIV, 'OP_DIV', 1));
exports.opcodes.set(exports.OP_MOD, new op_code_1.OpCode(exports.OP_MOD, 'OP_MOD', 1));
exports.opcodes.set(exports.OP_LSHIFT, new op_code_1.OpCode(exports.OP_LSHIFT, 'OP_LSHIFT', 1));
exports.opcodes.set(exports.OP_RSHIFT, new op_code_1.OpCode(exports.OP_RSHIFT, 'OP_RSHIFT', 1));
exports.opcodes.set(exports.OP_BOOLAND, new op_code_1.OpCode(exports.OP_BOOLAND, 'OP_BOOLAND', 1));
exports.opcodes.set(exports.OP_BOOLOR, new op_code_1.OpCode(exports.OP_BOOLOR, 'OP_BOOLOR', 1));
exports.opcodes.set(exports.OP_NUMEQUAL, new op_code_1.OpCode(exports.OP_NUMEQUAL, 'OP_NUMEQUAL', 1));
exports.opcodes.set(exports.OP_NUMEQUALVERIFY, new op_code_1.OpCode(exports.OP_NUMEQUALVERIFY, 'OP_NUMEQUALVERIFY', 1));
exports.opcodes.set(exports.OP_NUMNOTEQUAL, new op_code_1.OpCode(exports.OP_NUMNOTEQUAL, 'OP_NUMNOTEQUAL', 1));
exports.opcodes.set(exports.OP_LESSTHAN, new op_code_1.OpCode(exports.OP_LESSTHAN, 'OP_LESSTHAN', 1));
exports.opcodes.set(exports.OP_GREATERTHAN, new op_code_1.OpCode(exports.OP_GREATERTHAN, 'OP_GREATERTHAN', 1));
exports.opcodes.set(exports.OP_LESSTHANOREQUAL, new op_code_1.OpCode(exports.OP_LESSTHANOREQUAL, 'OP_LESSTHANOREQUAL', 1));
exports.opcodes.set(exports.OP_GREATERTHANOREQUAL, new op_code_1.OpCode(exports.OP_GREATERTHANOREQUAL, 'OP_GREATERTHANOREQUAL', 1));
exports.opcodes.set(exports.OP_MIN, new op_code_1.OpCode(exports.OP_MIN, 'OP_MIN', 1));
exports.opcodes.set(exports.OP_MAX, new op_code_1.OpCode(exports.OP_MAX, 'OP_MAX', 1));
exports.opcodes.set(exports.OP_WITHIN, new op_code_1.OpCode(exports.OP_WITHIN, 'OP_WITHIN', 1));
exports.opcodes.set(exports.OP_RIPEMD160, new op_code_1.OpCode(exports.OP_RIPEMD160, 'OP_RIPEMD160', 1));
exports.opcodes.set(exports.OP_SHA1, new op_code_1.OpCode(exports.OP_SHA1, 'OP_SHA1', 1));
exports.opcodes.set(exports.OP_SHA256, new op_code_1.OpCode(exports.OP_SHA256, 'OP_SHA256', 1));
exports.opcodes.set(exports.OP_STX, new op_code_1.OpCode(exports.OP_STX, 'OP_STX', 1));
exports.opcodes.set(exports.OP_CREATE, new op_code_1.OpCode(exports.OP_CREATE, 'OP_CREATE', 1));
exports.opcodes.set(exports.OP_CALL, new op_code_1.OpCode(exports.OP_CALL, 'OP_CALL', 1));
exports.opcodes.set(exports.OP_BLAKE256, new op_code_1.OpCode(exports.OP_BLAKE256, 'OP_BLAKE256', 1));
exports.opcodes.set(exports.OP_HASH160, new op_code_1.OpCode(exports.OP_HASH160, 'OP_HASH160', 1));
exports.opcodes.set(exports.OP_HASH256, new op_code_1.OpCode(exports.OP_HASH256, 'OP_HASH256', 1));
exports.opcodes.set(exports.OP_CODESEPARATOR, new op_code_1.OpCode(exports.OP_CODESEPARATOR, 'OP_CODESEPARATOR', 1));
exports.opcodes.set(exports.OP_CHECKSIG, new op_code_1.OpCode(exports.OP_CHECKSIG, 'OP_CHECKSIG', 1));
exports.opcodes.set(exports.OP_CHECKSIGVERIFY, new op_code_1.OpCode(exports.OP_CHECKSIGVERIFY, 'OP_CHECKSIGVERIFY', 1));
exports.opcodes.set(exports.OP_CHECKMULTISIG, new op_code_1.OpCode(exports.OP_CHECKMULTISIG, 'OP_CHECKMULTISIG', 1));
exports.opcodes.set(exports.OP_CHECKMULTISIGVERIFY, new op_code_1.OpCode(exports.OP_CHECKMULTISIGVERIFY, 'OP_CHECKMULTISIGVERIFY', 1));
exports.opcodes.set(exports.OP_NOP1, new op_code_1.OpCode(exports.OP_NOP1, 'OP_NOP1', 1));
exports.opcodes.set(exports.OP_NOP4, new op_code_1.OpCode(exports.OP_NOP4, 'OP_NOP4', 1));
exports.opcodes.set(exports.OP_NOP5, new op_code_1.OpCode(exports.OP_NOP5, 'OP_NOP5', 1));
exports.opcodes.set(exports.OP_NOP6, new op_code_1.OpCode(exports.OP_NOP6, 'OP_NOP6', 1));
exports.opcodes.set(exports.OP_NOP7, new op_code_1.OpCode(exports.OP_NOP7, 'OP_NOP7', 1));
exports.opcodes.set(exports.OP_NOP8, new op_code_1.OpCode(exports.OP_NOP8, 'OP_NOP8', 1));
exports.opcodes.set(exports.OP_NOP9, new op_code_1.OpCode(exports.OP_NOP9, 'OP_NOP9', 1));
exports.opcodes.set(exports.OP_NOP10, new op_code_1.OpCode(exports.OP_NOP10, 'OP_NOP10', 1));
exports.opcodes.set(exports.OP_SSTX, new op_code_1.OpCode(exports.OP_SSTX, 'OP_SSTX', 1));
exports.opcodes.set(exports.OP_SSGEN, new op_code_1.OpCode(exports.OP_SSGEN, 'OP_SSGEN', 1));
exports.opcodes.set(exports.OP_SSRTX, new op_code_1.OpCode(exports.OP_SSRTX, 'OP_SSRTX', 1));
exports.opcodes.set(exports.OP_SSTXCHANGE, new op_code_1.OpCode(exports.OP_SSTXCHANGE, 'OP_SSTXCHANGE', 1));
exports.opcodes.set(exports.OP_CHECKSIGALT, new op_code_1.OpCode(exports.OP_CHECKSIGALT, 'OP_CHECKSIGALT', 1));
exports.opcodes.set(exports.OP_CHECKSIGALTVERIFY, new op_code_1.OpCode(exports.OP_CHECKSIGALTVERIFY, 'OP_CHECKSIGALTVERIFY', 1));
exports.opcodes.set(exports.OP_INVALID249, new op_code_1.OpCode(exports.OP_INVALID249, 'OP_INVALID249', 1));
exports.opcodes.set(exports.OP_SMALLINTEGER, new op_code_1.OpCode(exports.OP_SMALLINTEGER, 'OP_SMALLINTEGER', 1));
exports.opcodes.set(exports.OP_PUBKEYS, new op_code_1.OpCode(exports.OP_PUBKEYS, 'OP_PUBKEYS', 1));
exports.opcodes.set(exports.OP_UNKNOWN252, new op_code_1.OpCode(exports.OP_UNKNOWN252, 'OP_UNKNOWN252', 1));
exports.opcodes.set(exports.OP_PUBKEYHASH, new op_code_1.OpCode(exports.OP_PUBKEYHASH, 'OP_PUBKEYHASH', 1));
exports.opcodes.set(exports.OP_PUBKEY, new op_code_1.OpCode(exports.OP_PUBKEY, 'OP_PUBKEY', 1));
exports.opcodes.set(exports.OP_INVALIDOPCODE, new op_code_1.OpCode(exports.OP_INVALIDOPCODE, 'OP_INVALIDOPCODE', 1));

},{"./op_code":36}],38:[function(require,module,exports){
(function (Buffer){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ParsedOpcode = void 0;
const opcode = __importStar(require("./opcode"));
class ParsedOpcode {
    constructor(opcode, data) {
        this._opcode = opcode;
        this.data = data || Buffer.alloc(0);
    }
    get opcode() {
        return this._opcode;
    }
    isDisabled() {
        switch (this.opcode.value) {
            case opcode.OP_CODESEPARATOR:
                return true;
            default:
                return false;
        }
    }
    alwaysIllegal() {
        switch (this.opcode.value) {
            case opcode.OP_VERIF:
            case opcode.OP_VERNOTIF:
                return true;
            default:
                return false;
        }
    }
    isConditional() {
        switch (this.opcode.value) {
            case opcode.OP_IF:
            case opcode.OP_NOTIF:
            case opcode.OP_ELSE:
            case opcode.OP_ENDIF:
                return true;
            default:
                return false;
        }
    }
    checkMinimalDataPush() {
        let data = this.data;
        let dataLen = data.length;
        let val = this.opcode.value;
        let name = this.opcode.name;
        if (dataLen == 0 && val == opcode.OP_0) {
            throw new Error(`zero length data push is encoded with opcode ${name} instead of OP_0`);
        }
        else if (dataLen == 1 && data[0] >= 1 && data[0] <= 16) {
            if (val != opcode.OP_1 + data[0] - 1) {
                throw new Error(`data push of the value ${data[0]} encoded with opcode ${name} instead of OP_${data[0]}`);
            }
        }
        else if (dataLen == 1 && data[0] == 0x81) {
            if (val != opcode.OP_1NEGATE) {
                throw new Error(`data push of the value -1 encoded with opcode ${name} instead of OP_1NEGATE`);
            }
        }
        else if (dataLen <= 75) {
            if (val != dataLen) {
                throw new Error(`data push of ${dataLen} bytes encoded with opcode ${name} instead of OP_DATA_${dataLen}`);
            }
        }
        else if (dataLen <= 255) {
            if (val != opcode.OP_PUSHDATA1) {
                throw new Error(`data push of ${dataLen} bytes encoded with opcode ${name} instead of OP_PUSHDATA1`);
            }
        }
        else if (dataLen <= 65535) {
            if (val != opcode.OP_PUSHDATA2) {
                throw new Error(`data push of ${dataLen} bytes encoded with opcode ${name} instead of OP_PUSHDATA2`);
            }
        }
    }
    print(oneline) {
        let name = this.opcode.name;
        if (oneline) {
            name = opcode.opcodeOnelineRepls.get(name) || name;
            // Nothing more to do for non-data push opcodes.
            if (this.opcode.length == 1) {
                return name;
            }
            return this.data.toString("hex");
        }
        if (this.opcode.length == 1) {
            return name;
        }
        let retString = name;
        let data = this.data;
        switch (this.opcode.length) {
            case -1:
                retString += data.length.toString();
                break;
            case -2:
                retString += data.length.toString();
                break;
            case -4:
                retString += data.length.toString();
                break;
        }
        return retString + data.toString("hex");
    }
    bytes() {
        let retbytes;
        if (this.opcode.length > 0) {
            retbytes = Buffer.alloc(this.opcode.length);
        }
        else {
            retbytes = Buffer.alloc(1 + this.data.length - this.opcode.length);
        }
        let offset = 0;
        retbytes.writeUInt8(this.opcode.value, offset);
        offset += 1;
        if (this.opcode.length == 1) {
            return retbytes;
        }
        let data = this.data;
        let nbytes = this.opcode.length;
        if (this.opcode.length < 0) {
            let l = data.length;
            switch (this.opcode.length) {
                case -1:
                    retbytes.writeUInt8(l, offset);
                    offset += 1;
                    nbytes = retbytes.readUInt8(1) + retbytes.length;
                    break;
                case -2:
                    retbytes.writeUInt8(l & 0xff, offset);
                    offset += 1;
                    retbytes.writeUInt8(l >> 8 & 0xff, offset);
                    offset += 1;
                    nbytes = retbytes.readUInt16BE(1) + retbytes.length;
                    break;
                case -4:
                    retbytes.writeUInt8(l & 0xff, offset);
                    offset += 1;
                    retbytes.writeUInt8((l >> 8) & 0xff, offset);
                    offset += 1;
                    retbytes.writeUInt8((l >> 16) & 0xff, offset);
                    offset += 1;
                    retbytes.writeUInt8((l >> 24) & 0xff, offset);
                    offset += 1;
                    nbytes = retbytes.readUInt32BE(1) + retbytes.length;
                    break;
            }
        }
        data.copy(retbytes, offset);
        if (retbytes.length != nbytes) {
            throw new Error(`internal consistency error - parsed opcode ${this.opcode.name} has data length ${retbytes.length} when ${nbytes} was expected`);
        }
        return retbytes;
    }
    toString() {
        return `[${this.data.join(', ')}]`;
    }
}
exports.ParsedOpcode = ParsedOpcode;

}).call(this,require("buffer").Buffer)
},{"./opcode":37,"buffer":62}],39:[function(require,module,exports){
(function (Buffer){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.pushedData = exports.removeOpcode = exports.unparseScript = exports.parseScript = exports.MAX_SCRIPT_ELEMENT_SIZE = exports.MAX_PUB_KEYS_PER_MULTI_SIG = exports.MAX_OPS_PER_SCRIPT = void 0;
const parsed_opcode_1 = require("./parsed_opcode");
const opcode = __importStar(require("./opcode"));
const { opcodes } = opcode;
exports.MAX_OPS_PER_SCRIPT = 255;
exports.MAX_PUB_KEYS_PER_MULTI_SIG = 20;
exports.MAX_SCRIPT_ELEMENT_SIZE = 2048;
function _parseScriptTemplate(script, opcodes) {
    let retScript = [];
    for (let i = 0; i < script.length;) {
        let instr = script[i];
        let op = opcodes.get(instr);
        if (op === undefined)
            continue;
        let pop = new parsed_opcode_1.ParsedOpcode(op);
        let len = op.length;
        if (len == 1) {
            i++;
        }
        else if (len > 1) {
            let scrLen = script.slice(i).length;
            if (scrLen < op.length) {
                throw new Error(`opcode ${op.name} requires ${op.length} bytes, but script only has ${scrLen} remaining`);
            }
            pop.data = script.slice(i + 1, i + op.length);
            i += op.length;
        }
        else if (len < 0) {
            let l;
            let off = i + 1;
            let offScr = script.slice(off);
            if (offScr.length < -op.length) {
                throw new Error(`opcode ${op.name} requires ${-op.length} bytes, but script only has ${offScr.length} remaining`);
            }
            switch (op.length) {
                case -1:
                    l = script[off];
                    break;
                case -2:
                    l = ((script[off + 1] << 8) | script[off]);
                    break;
                case -4:
                    l = ((script[off + 3] << 24) |
                        (script[off + 2] << 16) |
                        (script[off + 1] << 8) |
                        script[off]);
                    break;
                default:
                    throw new Error(`invalid opcode length ${op.length}`);
            }
            off += -op.length;
            if (l > offScr.length || l < 0) {
                throw new Error(`opcode ${op.name} pushes ${l} bytes, but script only has ${offScr.length} remaining`);
            }
            pop.data = script.slice(off, off + l);
            i += 1 - op.length + l;
        }
        retScript.push(pop);
    }
    return retScript;
}
function parseScript(script) {
    return _parseScriptTemplate(script, opcodes);
}
exports.parseScript = parseScript;
function unparseScript(pops) {
    let script = Buffer.allocUnsafe(0);
    for (let i = 0; i < pops.length; i++) {
        let pop = pops[i];
        let b = pop.bytes();
        script = Buffer.concat([script, b]);
    }
    return script;
}
exports.unparseScript = unparseScript;
function removeOpcode(pkscript, val) {
    let retScript = [];
    for (let i = 0; i < pkscript.length; i++) {
        let pop = pkscript[i];
        if (pop.opcode.value != val) {
            retScript.push(pop);
        }
    }
    return retScript;
}
exports.removeOpcode = removeOpcode;
function pushedData(script) {
    let pops = parseScript(script);
    let data = [];
    for (let i = 0; i < pops.length; i++) {
        let pop = pops[i];
        if (pop.data.length) {
            data.push(pop.data);
        }
        else if (pop.opcode.value == opcode.OP_0) {
            data.push(Buffer.alloc(0));
        }
    }
    return data;
}
exports.pushedData = pushedData;

}).call(this,require("buffer").Buffer)
},{"./opcode":37,"./parsed_opcode":38,"buffer":62}],40:[function(require,module,exports){
(function (Buffer){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScriptBuilder = void 0;
const engine_1 = require("./engine");
const script_1 = require("./script");
const opcode = __importStar(require("./opcode"));
class ScriptBuilder {
    constructor(from) {
        this._script = from || [];
    }
    add(code) {
        if (this._script.length > engine_1.MAX_SCRIPT_SIZE) {
            throw new Error(`adding an opcode would exceed the maximum allowed canonical script length of ${engine_1.MAX_SCRIPT_SIZE}`);
        }
        this._script.push(code);
        return this;
    }
    addOps(opcodes) {
        if (this._script.length + opcodes.length > engine_1.MAX_SCRIPT_SIZE) {
            throw new Error(`adding opcodes would exceed the maximum allowed canonical script length of MAX_SCRIPT_SIZE`);
        }
        this._script.push(...opcodes);
        return this;
    }
    addData(data) {
        let dataSize = canonicalDataSize(data);
        if (this._script.length + dataSize > engine_1.MAX_STACK_SIZE) {
            throw new Error(`adding ${dataSize} bytes of data would exceed the maximum allowed canonical script length of ${engine_1.MAX_STACK_SIZE}`);
        }
        let dataLen = data.length;
        if (dataLen > script_1.MAX_SCRIPT_ELEMENT_SIZE) {
            throw new Error(`'adding a data element of ${dataLen} bytes would exceed the maximum allowed script element size of ${script_1.MAX_SCRIPT_ELEMENT_SIZE}`);
        }
        return this._addData(data);
    }
    _addData(data) {
        let dataLen = data.length;
        if (dataLen == 0 || dataLen == 1 && data[0] == 0) {
            this._script.push(opcode.OP_0);
            return this;
        }
        else if (dataLen == 1 && data[0] <= 16) {
            this._script.push(opcode.OP_1 - 1 + data[0]);
            return this;
        }
        else if (dataLen == 1 && data[0] == 0x81) {
            this._script.push(opcode.OP_1NEGATE);
            return this;
        }
        if (dataLen < opcode.OP_PUSHDATA1) {
            this._script.push((opcode.OP_DATA_1 - 1) + dataLen);
        }
        else if (dataLen <= 0xff) {
            this._script.push(opcode.OP_PUSHDATA1, dataLen);
        }
        else if (dataLen <= 0xffff) {
            let buf = Buffer.allocUnsafe(2);
            buf.writeUInt16LE(dataLen, 0);
            this._script.push(opcode.OP_PUSHDATA2, ...buf.toJSON().data);
        }
        else {
            let buf = Buffer.allocUnsafe(4);
            buf.writeUInt32LE(dataLen, 0);
            this._script.push(opcode.OP_PUSHDATA4, ...buf.toJSON().data);
        }
        this._script.push(...data);
        return this;
    }
    reset() {
        this._script.length = 0;
    }
    script() {
        return Buffer.from(this._script);
    }
}
exports.ScriptBuilder = ScriptBuilder;
function canonicalDataSize(data) {
    let dataLen = data.length;
    if (dataLen == 0) {
        return 1;
    }
    else if (dataLen == 1 && data[0] <= 16) {
        return 1;
    }
    else if (dataLen == 1 && data[0] == 0x81) {
        return 1;
    }
    if (dataLen < opcode.OP_PUSHDATA1) {
        return 1 + dataLen;
    }
    else if (dataLen <= 0xff) {
        return 2 + dataLen;
    }
    else if (dataLen <= 0xffff) {
        return 3 + dataLen;
    }
    return 5 + dataLen;
}

}).call(this,require("buffer").Buffer)
},{"./engine":34,"./opcode":37,"./script":39,"buffer":62}],41:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScriptClosure = void 0;
class ScriptClosure {
    constructor(handle) {
        this._getScript = handle;
    }
    getScript(addr) {
        return this._getScript(addr);
    }
}
exports.ScriptClosure = ScriptClosure;

},{}],42:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Stack = void 0;
class Stack {
    constructor() {
        this._stk = [];
    }
    depth() {
        return this._stk.length;
    }
    _nipN(idx) {
        let sz = this._stk.length;
        if (idx < 0 || idx > sz - 1) {
            throw new Error(`index ${idx} is invalid for stack size ${sz}`);
        }
        let so = this._stk[sz - idx - 1];
        if (idx == 0) {
            this._stk = this._stk.slice(0, sz - 1);
        }
        else if (idx == sz - 1) {
            this._stk = this._stk.slice(1);
        }
        else {
            let s1 = this._stk.slice(sz - idx, sz);
            this._stk = this._stk.slice(0, sz - idx - 1);
            this._stk.push(...s1);
        }
        return so;
    }
    popByteArray() {
        return this._nipN(0);
    }
    dropN(n) {
        if (n < 1) {
            throw new Error(`attempt to drop ${n} items from stack`);
        }
        for (; n > 0; n--) {
            this.popByteArray();
        }
    }
    peekByteArray(idx) {
        let sz = this._stk.length;
        if (idx < 0 || idx >= sz) {
            throw new Error(`index ${idx} is invalid for stack size ${sz}`);
        }
        return this._stk[sz - idx - 1];
    }
    pushByteArray(so) {
        this._stk.push(so);
    }
    popBool() {
        let so = this.popByteArray();
        return _asBool(so);
    }
}
exports.Stack = Stack;
function _asBool(t) {
    for (let i = 0; i < t.length; i++) {
        if (t[i] != 0) {
            if (i == t.length - 1 && t[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

},{}],43:[function(require,module,exports){
(function (Buffer){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.payToContractCallPubKeyHash = exports.payToAddrScript = exports.payToSStxChange = exports.generateSStxAddrPush = exports.payToSStx = exports.hasP2SHScriptSigStakeOpCodes = exports.containsStakeOpCodes = exports.isAnyKindOfScriptHash = exports.isStakeScriptHash = exports.isStakeOutput = exports.isPushOnlyScript = exports.isPushOnly = exports.extractPkScriptAddrs = exports.getStakeOutSubscript = exports.extractPkScriptAltSigType = exports.extractOneBytePush = exports.getStakeOutSubclass = exports.getP2PKHOpCode = exports.getScriptClass = exports.isSideCall = exports.isSideCreate = exports.isSStxChange = exports.isStakeRevocation = exports.isStakeGen = exports.isStakeSubmission = exports.isNullData = exports.isMultiSig = exports.asSmallInt = exports.isSmallInt = exports.isPubkeyHashAlt = exports.isPubkeyHash = exports.isPubkeyAlt = exports.isOneByteMaxDataPush = exports.isScriptHash = exports.isStakeOpcode = exports.isPubkey = exports.SIDE_CALL_TY = exports.SIDE_CREATE_TY = exports.PUB_KEY_HASH_ALT_TY = exports.PUB_KEY_ALT_TY = exports.STAKE_SUB_CHANGE_TY = exports.STAKE_REVOCATION_TY = exports.STAKE_GEN_TY = exports.STAKE_SUBMISSION_TY = exports.NULL_DATA_TY = exports.MULTI_SIG_TY = exports.SCRIPT_HASH_TY = exports.PUB_KEY_HASH_TY = exports.PUB_KEY_TY = exports.NON_STANDARD_TY = exports.MAX_DATA_CARRIER_SIZE = void 0;
const opcode = __importStar(require("./opcode"));
const engine_1 = require("./engine");
const address_1 = require("@demos/address");
const dosec = __importStar(require("@demos/dosec"));
const script_1 = require("./script");
const script_builder_1 = require("./script_builder");
exports.MAX_DATA_CARRIER_SIZE = 256;
exports.NON_STANDARD_TY = 0;
exports.PUB_KEY_TY = 1;
exports.PUB_KEY_HASH_TY = 2;
exports.SCRIPT_HASH_TY = 3;
exports.MULTI_SIG_TY = 4;
exports.NULL_DATA_TY = 5;
exports.STAKE_SUBMISSION_TY = 6;
exports.STAKE_GEN_TY = 7;
exports.STAKE_REVOCATION_TY = 8;
exports.STAKE_SUB_CHANGE_TY = 9;
exports.PUB_KEY_ALT_TY = 10;
exports.PUB_KEY_HASH_ALT_TY = 11;
exports.SIDE_CREATE_TY = 12;
exports.SIDE_CALL_TY = 13;
function isPubkey(pops) {
    return pops.length == 2 &&
        (pops[0].data.length == 33 || pops[0].data.length == 65) &&
        pops[1].opcode.value == opcode.OP_CHECKSIG;
}
exports.isPubkey = isPubkey;
function isStakeOpcode(op) {
    return op.value >= opcode.OP_SSTX && op.value <= opcode.OP_SSTXCHANGE;
}
exports.isStakeOpcode = isStakeOpcode;
function isScriptHash(pops) {
    return pops.length == 3 &&
        pops[0].opcode.value == opcode.OP_HASH160 &&
        pops[1].opcode.value == opcode.OP_DATA_20 &&
        pops[2].opcode.value == opcode.OP_EQUAL;
}
exports.isScriptHash = isScriptHash;
function isOneByteMaxDataPush(po) {
    return po.opcode.value == opcode.OP_1 ||
        po.opcode.value == opcode.OP_2 ||
        po.opcode.value == opcode.OP_3 ||
        po.opcode.value == opcode.OP_4 ||
        po.opcode.value == opcode.OP_5 ||
        po.opcode.value == opcode.OP_6 ||
        po.opcode.value == opcode.OP_7 ||
        po.opcode.value == opcode.OP_8 ||
        po.opcode.value == opcode.OP_9 ||
        po.opcode.value == opcode.OP_10 ||
        po.opcode.value == opcode.OP_11 ||
        po.opcode.value == opcode.OP_12 ||
        po.opcode.value == opcode.OP_13 ||
        po.opcode.value == opcode.OP_14 ||
        po.opcode.value == opcode.OP_15 ||
        po.opcode.value == opcode.OP_16 ||
        po.opcode.value == opcode.OP_DATA_1;
}
exports.isOneByteMaxDataPush = isOneByteMaxDataPush;
function isPubkeyAlt(pops) {
    return pops.length == 3 &&
        pops[0].data.length < 512 &&
        isOneByteMaxDataPush(pops[1]) &&
        pops[2].opcode.value == opcode.OP_CHECKSIGALT;
}
exports.isPubkeyAlt = isPubkeyAlt;
function isPubkeyHash(pops) {
    return pops.length == 5 &&
        pops[0].opcode.value == opcode.OP_DUP &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUALVERIFY &&
        pops[4].opcode.value == opcode.OP_CHECKSIG;
}
exports.isPubkeyHash = isPubkeyHash;
function isPubkeyHashAlt(pops) {
    return pops.length == 6 &&
        pops[0].opcode.value == opcode.OP_DUP &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUALVERIFY &&
        isOneByteMaxDataPush(pops[4]) &&
        pops[5].opcode.value == opcode.OP_CHECKSIGALT;
}
exports.isPubkeyHashAlt = isPubkeyHashAlt;
function isSmallInt(op) {
    return op.value == opcode.OP_0 || (op.value >= opcode.OP_1 && op.value <= opcode.OP_16);
}
exports.isSmallInt = isSmallInt;
function asSmallInt(op) {
    if (op.value == opcode.OP_0) {
        return 0;
    }
    return op.value - (opcode.OP_1 - 1);
}
exports.asSmallInt = asSmallInt;
function isMultiSig(pops) {
    let l = pops.length;
    if (l < 4) {
        return false;
    }
    if (!isSmallInt(pops[0].opcode)) {
        return false;
    }
    if (!isSmallInt(pops[l - 2].opcode)) {
        return false;
    }
    if (pops[l - 1].opcode.value != opcode.OP_CHECKMULTISIG) {
        return false;
    }
    if (l - 2 - 1 != asSmallInt(pops[l - 2].opcode)) {
        return false;
    }
    for (let i = 1; i < l - 2; i++) {
        let pop = pops[i];
        if (pop.data.length != 33 && pop.data.length != 65) {
            return false;
        }
    }
    return true;
}
exports.isMultiSig = isMultiSig;
function isNullData(pops) {
    let l = pops.length;
    if (l == 1 && pops[0].opcode.value == opcode.OP_RETURN) {
        return true;
    }
    return l == 2 &&
        pops[0].opcode.value == opcode.OP_RETURN &&
        (isSmallInt(pops[1].opcode) || pops[1].opcode.value <= opcode.OP_PUSHDATA4) &&
        pops[1].data.length <= exports.MAX_DATA_CARRIER_SIZE;
}
exports.isNullData = isNullData;
function isStakeSubmission(pops) {
    if (pops.length == 6 &&
        pops[0].opcode.value == opcode.OP_SSTX &&
        pops[1].opcode.value == opcode.OP_DUP &&
        pops[2].opcode.value == opcode.OP_HASH160 &&
        pops[3].opcode.value == opcode.OP_DATA_20 &&
        pops[4].opcode.value == opcode.OP_EQUALVERIFY &&
        pops[5].opcode.value == opcode.OP_CHECKSIG) {
        return true;
    }
    return pops.length == 4 &&
        pops[0].opcode.value == opcode.OP_SSTX &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUAL;
}
exports.isStakeSubmission = isStakeSubmission;
function isStakeGen(pops) {
    if (pops.length == 6 &&
        pops[0].opcode.value == opcode.OP_SSGEN &&
        pops[1].opcode.value == opcode.OP_DUP &&
        pops[2].opcode.value == opcode.OP_HASH160 &&
        pops[3].opcode.value == opcode.OP_DATA_20 &&
        pops[4].opcode.value == opcode.OP_EQUALVERIFY &&
        pops[5].opcode.value == opcode.OP_CHECKSIG) {
        return true;
    }
    return pops.length == 4 &&
        pops[0].opcode.value == opcode.OP_SSGEN &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUAL;
}
exports.isStakeGen = isStakeGen;
function isStakeRevocation(pops) {
    if (pops.length == 6 &&
        pops[0].opcode.value == opcode.OP_SSRTX &&
        pops[1].opcode.value == opcode.OP_DUP &&
        pops[2].opcode.value == opcode.OP_HASH160 &&
        pops[3].opcode.value == opcode.OP_DATA_20 &&
        pops[4].opcode.value == opcode.OP_EQUALVERIFY &&
        pops[5].opcode.value == opcode.OP_CHECKSIG) {
        return true;
    }
    return pops.length == 4 &&
        pops[0].opcode.value == opcode.OP_SSRTX &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUAL;
}
exports.isStakeRevocation = isStakeRevocation;
function isSStxChange(pops) {
    if (pops.length == 6 &&
        pops[0].opcode.value == opcode.OP_SSTXCHANGE &&
        pops[1].opcode.value == opcode.OP_DUP &&
        pops[2].opcode.value == opcode.OP_HASH160 &&
        pops[3].opcode.value == opcode.OP_DATA_20 &&
        pops[4].opcode.value == opcode.OP_EQUALVERIFY &&
        pops[5].opcode.value == opcode.OP_CHECKSIG) {
        return true;
    }
    return pops.length == 4 &&
        pops[0].opcode.value == opcode.OP_SSTXCHANGE &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUAL;
}
exports.isSStxChange = isSStxChange;
function isSideCreate(pops) {
    return pops.length == 6 &&
        pops[0].opcode.value == opcode.OP_STX &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[5].opcode.value == opcode.OP_CREATE;
}
exports.isSideCreate = isSideCreate;
function isSideCall(pops) {
    return pops.length == 5 &&
        pops[0].opcode.value == opcode.OP_STX &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[4].opcode.value == opcode.OP_CALL;
}
exports.isSideCall = isSideCall;
function _typeOfScript(pops) {
    if (isPubkey(pops)) {
        return exports.PUB_KEY_TY;
    }
    else if (isPubkeyAlt(pops)) {
        return exports.PUB_KEY_ALT_TY;
    }
    else if (isPubkeyHash(pops)) {
        return exports.PUB_KEY_HASH_TY;
    }
    else if (isPubkeyHashAlt(pops)) {
        return exports.PUB_KEY_HASH_ALT_TY;
    }
    else if (isScriptHash(pops)) {
        return exports.SCRIPT_HASH_TY;
    }
    else if (isMultiSig(pops)) {
        return exports.MULTI_SIG_TY;
    }
    else if (isNullData(pops)) {
        return exports.NULL_DATA_TY;
    }
    else if (isStakeSubmission(pops)) {
        return exports.STAKE_SUBMISSION_TY;
    }
    else if (isStakeGen(pops)) {
        return exports.STAKE_GEN_TY;
    }
    else if (isStakeRevocation(pops)) {
        return exports.STAKE_REVOCATION_TY;
    }
    else if (isSStxChange(pops)) {
        return exports.STAKE_SUB_CHANGE_TY;
    }
    else if (isSideCreate(pops)) {
        return exports.SIDE_CREATE_TY;
    }
    else if (isSideCall(pops)) {
        return exports.SIDE_CALL_TY;
    }
    return exports.NON_STANDARD_TY;
}
function getScriptClass(version, script) {
    if (version != engine_1.DEFAULT_SCRIPT_VERSION) {
        return exports.NON_STANDARD_TY;
    }
    let pops;
    try {
        pops = script_1.parseScript(script);
    }
    catch (e) {
        return exports.NON_STANDARD_TY;
    }
    return _typeOfScript(pops);
}
exports.getScriptClass = getScriptClass;
function getP2PKHOpCode(pkScript) {
    let cls = getScriptClass(engine_1.DEFAULT_SCRIPT_VERSION, pkScript);
    switch (cls) {
        case exports.STAKE_SUBMISSION_TY:
            return opcode.OP_SSTX;
        case exports.STAKE_GEN_TY:
            return opcode.OP_SSGEN;
        case exports.STAKE_REVOCATION_TY:
            return opcode.OP_SSRTX;
        case exports.STAKE_SUB_CHANGE_TY:
            return opcode.OP_SSTXCHANGE;
    }
    return opcode.OP_NOP10;
}
exports.getP2PKHOpCode = getP2PKHOpCode;
function getStakeOutSubclass(pkScript) {
    let pkPops = script_1.parseScript(pkScript);
    let cls = _typeOfScript(pkPops);
    let isStake = cls == exports.STAKE_SUBMISSION_TY ||
        cls == exports.STAKE_GEN_TY ||
        cls == exports.STAKE_REVOCATION_TY ||
        cls == exports.STAKE_SUB_CHANGE_TY;
    let subClass = exports.NON_STANDARD_TY;
    if (isStake) {
        let stakeSubscript = [];
        for (let i = 0; i < pkPops.length; i++) {
            let pop = pkPops[i];
            if (isStakeOpcode(pop.opcode)) {
                continue;
            }
            stakeSubscript.push(pop);
        }
        subClass = _typeOfScript(stakeSubscript);
    }
    else {
        throw new Error("not a stake output");
    }
    return subClass;
}
exports.getStakeOutSubclass = getStakeOutSubclass;
function extractOneBytePush(po) {
    if (!isOneByteMaxDataPush(po)) {
        return -1;
    }
    if (po.opcode.value === opcode.OP_1 ||
        po.opcode.value === opcode.OP_2 ||
        po.opcode.value === opcode.OP_3 ||
        po.opcode.value === opcode.OP_4 ||
        po.opcode.value === opcode.OP_5 ||
        po.opcode.value === opcode.OP_6 ||
        po.opcode.value === opcode.OP_7 ||
        po.opcode.value === opcode.OP_8 ||
        po.opcode.value === opcode.OP_9 ||
        po.opcode.value === opcode.OP_10 ||
        po.opcode.value === opcode.OP_11 ||
        po.opcode.value === opcode.OP_12 ||
        po.opcode.value === opcode.OP_13 ||
        po.opcode.value === opcode.OP_14 ||
        po.opcode.value === opcode.OP_15 ||
        po.opcode.value === opcode.OP_16) {
        return po.opcode.value - 80;
    }
    return po.data[0];
}
exports.extractOneBytePush = extractOneBytePush;
function extractPkScriptAltSigType(pkScript) {
    let pops = script_1.parseScript(pkScript);
    let isPKA = isPubkeyAlt(pops);
    let isPKHA = isPubkeyHashAlt(pops);
    if (!(isPKA || isPKHA)) {
        throw new Error("wrong script type");
    }
    let sigTypeLoc = 1;
    if (isPKHA) {
        sigTypeLoc = 4;
    }
    let val = extractOneBytePush(pops[sigTypeLoc]);
    if (val < 0) {
        throw new Error("bad type push");
    }
    switch (val) {
        case 1:
            return dosec.SignatureType.STEd25519;
        case 2:
            return dosec.SignatureType.STSchnorrSecp256k1;
        default:
            break;
    }
    throw new Error("bad signature scheme type");
}
exports.extractPkScriptAltSigType = extractPkScriptAltSigType;
function getStakeOutSubscript(pkScript) {
    return pkScript.slice(1);
}
exports.getStakeOutSubscript = getStakeOutSubscript;
function extractPkScriptAddrs(version, pkScript, net) {
    if (version != engine_1.DEFAULT_SCRIPT_VERSION) {
        throw new Error("invalid script version");
    }
    let addrs = [];
    let requiredSigs = 1;
    let addr;
    let pops = script_1.parseScript(pkScript);
    let scriptClass = _typeOfScript(pops);
    switch (scriptClass) {
        case exports.PUB_KEY_HASH_TY:
            requiredSigs = 1;
            try {
                addr = new address_1.AddressPubKeyHash(pops[2].data, net, dosec.SignatureType.STEcdsaSecp256k1);
                addrs.push(addr);
            }
            catch (_) {
            }
            break;
        case exports.PUB_KEY_HASH_ALT_TY:
            requiredSigs = 1;
            try {
                let suite = extractPkScriptAltSigType(pkScript);
                addr = new address_1.AddressPubKeyHash(pops[2].data, net, suite);
                addrs.push(addr);
            }
            catch (_) {
            }
            break;
        case exports.STAKE_SUBMISSION_TY:
        case exports.STAKE_GEN_TY:
        case exports.STAKE_REVOCATION_TY:
        case exports.STAKE_SUB_CHANGE_TY:
            try {
                let data = extractPkScriptAddrs(version, getStakeOutSubscript(pkScript), net);
                addrs.push(...data[1]);
                requiredSigs = data[2];
            }
            catch (_) {
            }
            break;
    }
    return [scriptClass, addrs, requiredSigs];
}
exports.extractPkScriptAddrs = extractPkScriptAddrs;
function isPushOnly(pops) {
    for (let i = 0; i < pops.length; i++) {
        let pop = pops[i];
        if (pop.opcode.value > opcode.OP_16) {
            return false;
        }
    }
    return true;
}
exports.isPushOnly = isPushOnly;
function isPushOnlyScript(script) {
    let pops;
    try {
        pops = script_1.parseScript(script);
    }
    catch (_) {
        return false;
    }
    return isPushOnly(pops);
}
exports.isPushOnlyScript = isPushOnlyScript;
function isStakeOutput(pkScript) {
    let pkPops = script_1.parseScript(pkScript);
    let cls = _typeOfScript(pkPops);
    return cls == exports.STAKE_SUBMISSION_TY ||
        cls == exports.STAKE_GEN_TY ||
        cls == exports.STAKE_REVOCATION_TY ||
        cls == exports.STAKE_SUB_CHANGE_TY;
}
exports.isStakeOutput = isStakeOutput;
function isStakeScriptHash(pops) {
    return pops.length == 4 &&
        isStakeOpcode(pops[0].opcode) &&
        pops[1].opcode.value == opcode.OP_HASH160 &&
        pops[2].opcode.value == opcode.OP_DATA_20 &&
        pops[3].opcode.value == opcode.OP_EQUAL;
}
exports.isStakeScriptHash = isStakeScriptHash;
function isAnyKindOfScriptHash(pops) {
    return isScriptHash(pops) || isStakeScriptHash(pops);
}
exports.isAnyKindOfScriptHash = isAnyKindOfScriptHash;
function containsStakeOpCodes(pkScript) {
    let shPops = script_1.parseScript(pkScript);
    for (let i = 0; i < shPops.length; i++) {
        let pop = shPops[i];
        if (isStakeOpcode(pop.opcode)) {
            return true;
        }
    }
    return false;
}
exports.containsStakeOpCodes = containsStakeOpCodes;
function hasP2SHScriptSigStakeOpCodes(version, scriptSig, scriptPubKey) {
    let cls = getScriptClass(version, scriptPubKey);
    if (isStakeOutput(scriptPubKey)) {
        cls = getStakeOutSubclass(scriptPubKey);
    }
    if (cls == exports.SCRIPT_HASH_TY) {
        let pData = script_1.pushedData(scriptSig);
        if (!pData.length) {
            throw new Error("script has no pushed data");
        }
        let shScript = pData[pData.length - 1];
        if (containsStakeOpCodes(shScript)) {
            throw new Error("stake opcodes were found in a p2sh script");
        }
    }
}
exports.hasP2SHScriptSigStakeOpCodes = hasP2SHScriptSigStakeOpCodes;
function payToSStx(addr) {
    if (addr) {
        let scriptType = exports.PUB_KEY_HASH_TY;
        if (addr instanceof address_1.AddressPubKeyHash) {
            if (addr.DSA() != dosec.SignatureType.STEcdsaSecp256k1) {
                throw new Error("unable to generate payment script for unsupported digital signature algorithm");
            }
        }
        else if (addr instanceof address_1.AddressScriptHash) {
            scriptType = exports.SCRIPT_HASH_TY;
        }
        else {
            throw new Error(`unable to generate payment script for unsupported address type ${addr.encode()}`);
        }
        let hash = addr.hash160();
        if (scriptType == exports.PUB_KEY_HASH_TY) {
            return new script_builder_1.ScriptBuilder()
                .add(opcode.OP_SSTX)
                .add(opcode.OP_DUP)
                .add(opcode.OP_HASH160)
                .addData(hash)
                .add(opcode.OP_EQUALVERIFY)
                .add(opcode.OP_CHECKSIG)
                .script();
        }
        return new script_builder_1.ScriptBuilder()
            .add(opcode.OP_SSTX)
            .add(opcode.OP_HASH160)
            .addData(hash)
            .add(opcode.OP_EQUAL)
            .script();
    }
    else {
        throw new Error("unable to generate payment script for null address");
    }
}
exports.payToSStx = payToSStx;
function generateSStxAddrPush(addr, amount, limits) {
    if (addr) {
        let scriptType = exports.PUB_KEY_HASH_TY;
        if (addr instanceof address_1.AddressPubKeyHash) {
            if (addr.DSA() != dosec.SignatureType.STEcdsaSecp256k1) {
                throw new Error("unable to generate payment script for unsupported digital signature algorithm");
            }
        }
        else if (addr instanceof address_1.AddressScriptHash) {
            scriptType = exports.SCRIPT_HASH_TY;
        }
        else {
            throw new Error(`unable to generate payment script for unsupported address type ${addr.encode()}`);
        }
        let adBytes = Buffer.alloc(20 + 8 + 2);
        let offset = 0;
        let hash = addr.hash160();
        hash.copy(adBytes, offset);
        offset += hash.length;
        amount.toBuffer("le", 8).copy(adBytes, offset);
        offset += 8;
        adBytes.writeUInt16LE(limits, offset);
        if (scriptType == exports.SCRIPT_HASH_TY) {
            adBytes.writeUInt8(adBytes.readUInt8(27) | (1 << 7), 27);
        }
        return new script_builder_1.ScriptBuilder()
            .add(opcode.OP_RETURN)
            .addData(adBytes)
            .script();
    }
    else {
        throw new Error("unable to generate payment script for null address");
    }
}
exports.generateSStxAddrPush = generateSStxAddrPush;
function payToSStxChange(addr) {
    if (addr) {
        let scriptType = exports.PUB_KEY_HASH_TY;
        if (addr instanceof address_1.AddressPubKeyHash) {
            if (addr.DSA() != dosec.SignatureType.STEcdsaSecp256k1) {
                throw new Error("unable to generate payment script for unsupported digital signature algorithm");
            }
        }
        else if (addr instanceof address_1.AddressScriptHash) {
            scriptType = exports.SCRIPT_HASH_TY;
        }
        else {
            throw new Error(`unable to generate payment script for unsupported address type ${addr.encode()}`);
        }
        let hash = addr.hash160();
        if (scriptType == exports.PUB_KEY_HASH_TY) {
            return new script_builder_1.ScriptBuilder()
                .add(opcode.OP_SSTXCHANGE)
                .add(opcode.OP_DUP)
                .add(opcode.OP_HASH160)
                .addData(hash)
                .add(opcode.OP_EQUALVERIFY)
                .add(opcode.OP_CHECKSIG)
                .script();
        }
        return new script_builder_1.ScriptBuilder()
            .add(opcode.OP_SSTXCHANGE)
            .add(opcode.OP_HASH160)
            .addData(hash)
            .add(opcode.OP_EQUAL)
            .script();
    }
    else {
        throw new Error("unable to generate payment script for null address");
    }
}
exports.payToSStxChange = payToSStxChange;
function payToAddrScript(addr) {
    if (addr == null) {
        throw new Error("unable to generate payment script for nil address");
    }
    if (addr instanceof address_1.AddressPubKeyHash) {
        switch (addr.DSA()) {
            case dosec.SignatureType.STEcdsaSecp256k1:
                return _payToPubKeyHashScript(addr.hash160());
            case dosec.SignatureType.STEd25519:
                return _payToPubKeyHashEdwardsScript(addr.hash160());
            case dosec.SignatureType.STSchnorrSecp256k1:
                return _payToPubKeyHashSchnorrScript(addr.hash160());
        }
    }
    else if (addr instanceof address_1.AddressScriptHash) {
        return _payToScriptHashScript(addr.hash160());
    }
    throw new Error("unable to generate payment script for unsupported address type");
}
exports.payToAddrScript = payToAddrScript;
function _payToPubKeyHashScript(pubKeyHash) {
    return new script_builder_1.ScriptBuilder()
        .add(opcode.OP_DUP)
        .add(opcode.OP_HASH160)
        .addData(pubKeyHash)
        .add(opcode.OP_EQUALVERIFY)
        .add(opcode.OP_CHECKSIG)
        .script();
}
function _payToPubKeyHashEdwardsScript(pubKeyHash) {
    let edwardsData = Buffer.from([dosec.SignatureType.STEd25519]);
    return new script_builder_1.ScriptBuilder()
        .add(opcode.OP_DUP)
        .add(opcode.OP_HASH160)
        .addData(pubKeyHash)
        .add(opcode.OP_EQUALVERIFY)
        .addData(edwardsData)
        .add(opcode.OP_CHECKSIGALT)
        .script();
}
function _payToPubKeyHashSchnorrScript(pubKeyHash) {
    let schnorrData = Buffer.from([dosec.SignatureType.STSchnorrSecp256k1]);
    return new script_builder_1.ScriptBuilder()
        .add(opcode.OP_DUP)
        .add(opcode.OP_HASH160)
        .addData(pubKeyHash)
        .add(opcode.OP_EQUALVERIFY)
        .addData(schnorrData)
        .add(opcode.OP_CHECKSIGALT)
        .script();
}
function _payToScriptHashScript(scriptHash) {
    return new script_builder_1.ScriptBuilder()
        .add(opcode.OP_HASH160)
        .addData(scriptHash)
        .add(opcode.OP_EQUAL)
        .script();
}
function payToContractCallPubKeyHash(pubKeyHash, data) {
    return new script_builder_1.ScriptBuilder()
        .add(opcode.OP_STX)
        .add(opcode.OP_HASH160)
        .addData(pubKeyHash)
        .addData(data)
        .add(opcode.OP_CALL)
        .script();
}
exports.payToContractCallPubKeyHash = payToContractCallPubKeyHash;

}).call(this,require("buffer").Buffer)
},{"./engine":34,"./opcode":37,"./script":39,"./script_builder":40,"@demos/address":1,"@demos/dosec":17,"buffer":62}],44:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./opcode"), exports);
__exportStar(require("./parsed_opcode"), exports);
__exportStar(require("./standard"), exports);
__exportStar(require("./script"), exports);
__exportStar(require("./script_builder"), exports);
__exportStar(require("./engine"), exports);
__exportStar(require("./key_closure"), exports);
__exportStar(require("./script_closure"), exports);

},{"./engine":34,"./key_closure":35,"./opcode":37,"./parsed_opcode":38,"./script":39,"./script_builder":40,"./script_closure":41,"./standard":43}],45:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sumOutputSerializeSizes = exports.varIntSerializeSize = exports.estimateOutputSize = exports.estimateInputSize = exports.estimateSerializeSizeFromScriptSizes = exports.estimateSerializeSize = exports.MAX_UINT_32 = exports.MAX_UINT_16 = exports.MAX_UINT_8 = exports.P2PKH_OUTPUT_SIZE = exports.TICKET_COMMITMENT_SCRIPT_SIZE = exports.P2SH_PK_SCRIPT_SIZE = exports.P2PKH_PK_SCRIPT_SIZE = exports.REDEEM_P2PKH_INPUT_SIZE = exports.REDEEM_P2SH_SIG_SCRIPT_SIZE = exports.REDEEM_P2PKH_SIG_SCRIPT_SIZE = exports.REDEEM_P2PK_SIG_SCRIPT_SIZE = void 0;
exports.REDEEM_P2PK_SIG_SCRIPT_SIZE = 1 + 73;
exports.REDEEM_P2PKH_SIG_SCRIPT_SIZE = 1 + 73 + 1 + 33;
exports.REDEEM_P2SH_SIG_SCRIPT_SIZE = 1 + 73 + 1 + 1 + 33 + 1;
exports.REDEEM_P2PKH_INPUT_SIZE = 32 + 4 + 1 + 8 + 4 + 4 + 1 + exports.REDEEM_P2PKH_SIG_SCRIPT_SIZE + 4;
exports.P2PKH_PK_SCRIPT_SIZE = 1 + 1 + 1 + 20 + 1 + 1;
exports.P2SH_PK_SCRIPT_SIZE = 1 + 1 + 20 + 1;
exports.TICKET_COMMITMENT_SCRIPT_SIZE = 1 + 1 + 20 + 8 + 2;
exports.P2PKH_OUTPUT_SIZE = 8 + 2 + 1 + 25;
exports.MAX_UINT_8 = 1 << 8 - 1;
exports.MAX_UINT_16 = 1 << 16 - 1;
exports.MAX_UINT_32 = 1 << 32 - 1;
function estimateSerializeSize(scriptSizes, txOuts, changeScriptSize) {
    let txInsSize = 0;
    for (let i = 0; i < scriptSizes.length; i++) {
        txInsSize += estimateInputSize(scriptSizes[i]);
    }
    let inputCount = scriptSizes.length;
    let outputCount = txOuts.length;
    let changeSize = 0;
    if (changeScriptSize > 0) {
        changeSize = estimateOutputSize(changeScriptSize);
        outputCount++;
    }
    // 12 additional bytes are for version, locktime and expiry.
    return 12 + (2 * varIntSerializeSize(inputCount)) +
        varIntSerializeSize(outputCount) +
        txInsSize +
        sumOutputSerializeSizes(txOuts) +
        changeSize;
}
exports.estimateSerializeSize = estimateSerializeSize;
function estimateSerializeSizeFromScriptSizes(inputSizes, outputSizes, changeScriptSize) {
    // Generate and sum up the estimated sizes of the inputs.
    let txInsSize = 0;
    for (let i = 0; i < inputSizes.length; i++) {
        txInsSize += estimateInputSize(inputSizes[i]);
    }
    let txOutsSize = 0;
    for (let i = 0; i < outputSizes.length; i++) {
        txOutsSize += estimateOutputSize(outputSizes[i]);
    }
    let inputCount = inputSizes.length;
    let outputCount = outputSizes.length;
    let changeSize = 0;
    if (changeScriptSize > 0) {
        changeSize = estimateOutputSize(changeScriptSize);
        outputCount++;
    }
    // 12 additional bytes are for version, locktime and expiry.
    return 12 + (2 * varIntSerializeSize(inputCount)) +
        varIntSerializeSize(outputCount) +
        txInsSize + txOutsSize + changeSize;
}
exports.estimateSerializeSizeFromScriptSizes = estimateSerializeSizeFromScriptSizes;
function estimateInputSize(scriptSize) {
    return 32 + 4 + 1 + 8 + 4 + 4 + varIntSerializeSize(scriptSize) + scriptSize + 4;
}
exports.estimateInputSize = estimateInputSize;
function estimateOutputSize(scriptSize) {
    return 8 + 2 + varIntSerializeSize(scriptSize) + scriptSize;
}
exports.estimateOutputSize = estimateOutputSize;
function varIntSerializeSize(val) {
    // The value is small enough to be represented by itself, so it's
    // just 1 byte.
    if (val < 0xfd) {
        return 1;
    }
    // Discriminant 1 byte plus 2 bytes for the uint16.
    if (val <= exports.MAX_UINT_16) {
        return 3;
    }
    // Discriminant 1 byte plus 4 bytes for the uint32.
    if (val <= exports.MAX_UINT_32) {
        return 5;
    }
    // Discriminant 1 byte plus 8 bytes for the uint64.
    return 9;
}
exports.varIntSerializeSize = varIntSerializeSize;
function sumOutputSerializeSizes(outputs) {
    let serializeSize = 0;
    for (let i = 0; i < outputs.length; i++) {
        serializeSize += outputs[i].serializeSize();
    }
    return serializeSize;
}
exports.sumOutputSerializeSizes = sumOutputSerializeSizes;

},{}],46:[function(require,module,exports){
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Amount = exports.MAX_AMOUNT = exports.ATOMS_PER_COIN = exports.ATOMS_PER_CENT = void 0;
const bn_js_1 = __importDefault(require("bn.js"));
exports.ATOMS_PER_CENT = 1000000;
exports.ATOMS_PER_COIN = 100000000;
exports.MAX_AMOUNT = 210000000;
let Amount = /** @class */ (() => {
    class Amount {
        constructor(amount) {
            this._value = new bn_js_1.default(amount);
        }
        toUnit(u = Amount.AMOUNT_ATOM) {
            return this._value.div(new bn_js_1.default(Math.pow(10, u + 8))).toNumber();
        }
        format(u) {
            let units = ' ';
            switch (u) {
                case Amount.AMOUNT_MEGA_COIN:
                    units += 'MDOS';
                    break;
                case Amount.AMOUNT_KILO_COIN:
                    units += 'kDOS';
                    break;
                case Amount.AMOUNT_COIN:
                    units += 'DOS';
                    break;
                case Amount.AMOUNT_MILLI_COIN:
                    units += 'mDOS';
                    break;
                case Amount.AMOUNT_MICRO_COIN:
                    units += 'μDOS';
                    break;
                case Amount.AMOUNT_ATOM:
                    units += 'Atom';
                    break;
                default:
                    return `1e${u} DOS`;
            }
            return this.toUnit(u).toString() + units;
        }
        toString() {
            return this.format(Amount.AMOUNT_COIN);
        }
        add(other) {
            return new Amount(this._value.add(other._value).toNumber());
        }
        sub(other) {
            return new Amount(this._value.sub(other._value).toNumber());
        }
        compareTo(other) {
            return this._value.cmp(other._value);
        }
        toBuffer(endian, length) {
            return this._value.toBuffer(endian, length);
        }
    }
    Amount.AMOUNT_MEGA_COIN = 6;
    Amount.AMOUNT_KILO_COIN = 3;
    Amount.AMOUNT_COIN = 0;
    Amount.AMOUNT_MILLI_COIN = -3;
    Amount.AMOUNT_MICRO_COIN = -6;
    Amount.AMOUNT_ATOM = -8;
    return Amount;
})();
exports.Amount = Amount;

},{"bn.js":59}],47:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !exports.hasOwnProperty(p)) __createBinding(exports, m, p);
}
Object.defineProperty(exports, "__esModule", { value: true });
__exportStar(require("./amount"), exports);

},{"./amount":46}],48:[function(require,module,exports){
'use strict'
// base-x encoding / decoding
// Copyright (c) 2018 base-x contributors
// Copyright (c) 2014-2018 The Bitcoin Core developers (base58.cpp)
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
// @ts-ignore
var _Buffer = require('safe-buffer').Buffer
function base (ALPHABET) {
  if (ALPHABET.length >= 255) { throw new TypeError('Alphabet too long') }
  var BASE_MAP = new Uint8Array(256)
  for (var j = 0; j < BASE_MAP.length; j++) {
    BASE_MAP[j] = 255
  }
  for (var i = 0; i < ALPHABET.length; i++) {
    var x = ALPHABET.charAt(i)
    var xc = x.charCodeAt(0)
    if (BASE_MAP[xc] !== 255) { throw new TypeError(x + ' is ambiguous') }
    BASE_MAP[xc] = i
  }
  var BASE = ALPHABET.length
  var LEADER = ALPHABET.charAt(0)
  var FACTOR = Math.log(BASE) / Math.log(256) // log(BASE) / log(256), rounded up
  var iFACTOR = Math.log(256) / Math.log(BASE) // log(256) / log(BASE), rounded up
  function encode (source) {
    if (Array.isArray(source) || source instanceof Uint8Array) { source = _Buffer.from(source) }
    if (!_Buffer.isBuffer(source)) { throw new TypeError('Expected Buffer') }
    if (source.length === 0) { return '' }
        // Skip & count leading zeroes.
    var zeroes = 0
    var length = 0
    var pbegin = 0
    var pend = source.length
    while (pbegin !== pend && source[pbegin] === 0) {
      pbegin++
      zeroes++
    }
        // Allocate enough space in big-endian base58 representation.
    var size = ((pend - pbegin) * iFACTOR + 1) >>> 0
    var b58 = new Uint8Array(size)
        // Process the bytes.
    while (pbegin !== pend) {
      var carry = source[pbegin]
            // Apply "b58 = b58 * 256 + ch".
      var i = 0
      for (var it1 = size - 1; (carry !== 0 || i < length) && (it1 !== -1); it1--, i++) {
        carry += (256 * b58[it1]) >>> 0
        b58[it1] = (carry % BASE) >>> 0
        carry = (carry / BASE) >>> 0
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i
      pbegin++
    }
        // Skip leading zeroes in base58 result.
    var it2 = size - length
    while (it2 !== size && b58[it2] === 0) {
      it2++
    }
        // Translate the result into a string.
    var str = LEADER.repeat(zeroes)
    for (; it2 < size; ++it2) { str += ALPHABET.charAt(b58[it2]) }
    return str
  }
  function decodeUnsafe (source) {
    if (typeof source !== 'string') { throw new TypeError('Expected String') }
    if (source.length === 0) { return _Buffer.alloc(0) }
    var psz = 0
        // Skip leading spaces.
    if (source[psz] === ' ') { return }
        // Skip and count leading '1's.
    var zeroes = 0
    var length = 0
    while (source[psz] === LEADER) {
      zeroes++
      psz++
    }
        // Allocate enough space in big-endian base256 representation.
    var size = (((source.length - psz) * FACTOR) + 1) >>> 0 // log(58) / log(256), rounded up.
    var b256 = new Uint8Array(size)
        // Process the characters.
    while (source[psz]) {
            // Decode character
      var carry = BASE_MAP[source.charCodeAt(psz)]
            // Invalid character
      if (carry === 255) { return }
      var i = 0
      for (var it3 = size - 1; (carry !== 0 || i < length) && (it3 !== -1); it3--, i++) {
        carry += (BASE * b256[it3]) >>> 0
        b256[it3] = (carry % 256) >>> 0
        carry = (carry / 256) >>> 0
      }
      if (carry !== 0) { throw new Error('Non-zero carry') }
      length = i
      psz++
    }
        // Skip trailing spaces.
    if (source[psz] === ' ') { return }
        // Skip leading zeroes in b256.
    var it4 = size - length
    while (it4 !== size && b256[it4] === 0) {
      it4++
    }
    var vch = _Buffer.allocUnsafe(zeroes + (size - it4))
    vch.fill(0x00, 0, zeroes)
    var j = zeroes
    while (it4 !== size) {
      vch[j++] = b256[it4++]
    }
    return vch
  }
  function decode (string) {
    var buffer = decodeUnsafe(string)
    if (buffer) { return buffer }
    throw new Error('Non-base' + BASE + ' character')
  }
  return {
    encode: encode,
    decodeUnsafe: decodeUnsafe,
    decode: decode
  }
}
module.exports = base

},{"safe-buffer":82}],49:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(
      uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
    ))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],50:[function(require,module,exports){
module.exports = require('./lib/api')(require('./lib'))

},{"./lib":58,"./lib/api":52}],51:[function(require,module,exports){
(function (Buffer){
const Transform = require('readable-stream').Transform

module.exports = class Blake extends Transform {
  constructor (engine, options) {
    super(options)

    this._engine = engine
    this._finalized = false
  }

  _transform (chunk, encoding, callback) {
    let error = null
    try {
      this.update(chunk, encoding)
    } catch (err) {
      error = err
    }

    callback(error)
  }

  _flush (callback) {
    let error = null
    try {
      this.push(this.digest())
    } catch (err) {
      error = err
    }

    callback(error)
  }

  update (data, encoding) {
    if (!Buffer.isBuffer(data) && typeof data !== 'string') throw new TypeError('Data must be a string or a buffer')
    if (this._finalized) throw new Error('Digest already called')
    if (!Buffer.isBuffer(data)) data = Buffer.from(data, encoding)

    this._engine.update(data)

    return this
  }

  digest (encoding) {
    if (this._finalized) throw new Error('Digest already called')
    this._finalized = true

    let digest = this._engine.digest()
    if (encoding !== undefined) digest = digest.toString(encoding)

    return digest
  }
}

}).call(this,require("buffer").Buffer)
},{"buffer":62,"readable-stream":81}],52:[function(require,module,exports){
const Blake = require('./blake')

module.exports = (engines) => {
  const getEngine = (algorithm) => {
    const hash = typeof algorithm === 'string' ? algorithm.toLowerCase() : algorithm
    switch (hash) {
      case 'blake224': return engines.Blake224
      case 'blake256': return engines.Blake256
      case 'blake384': return engines.Blake384
      case 'blake512': return engines.Blake512

      default: throw new Error('Invald algorithm: ' + algorithm)
    }
  }

  return (algorithm, options) => {
    const Engine = getEngine(algorithm)
    return new Blake(new Engine(), options)
  }
}

},{"./blake":51}],53:[function(require,module,exports){
(function (Buffer){
class Blake {
  _lengthCarry (arr) {
    for (let j = 0; j < arr.length; ++j) {
      if (arr[j] < 0x0100000000) break
      arr[j] -= 0x0100000000
      arr[j + 1] += 1
    }
  }

  update (data) {
    const block = this._block
    let offset = 0

    while (this._blockOffset + data.length - offset >= block.length) {
      for (let i = this._blockOffset; i < block.length;) block[i++] = data[offset++]

      this._length[0] += block.length * 8
      this._lengthCarry(this._length)

      this._compress()
      this._blockOffset = 0
    }

    while (offset < data.length) block[this._blockOffset++] = data[offset++]
  }
}

Blake.sigma = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]
]

Blake.u256 = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
]

Blake.u512 = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
  0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
  0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
  0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
  0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69
]

Blake.padding = Buffer.from([
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
])

module.exports = Blake

}).call(this,require("buffer").Buffer)
},{"buffer":62}],54:[function(require,module,exports){
(function (Buffer){
const Blake256 = require('./blake256')

const zo = Buffer.from([0x00])
const oo = Buffer.from([0x80])

module.exports = class Blake224 extends Blake256 {
  constructor () {
    super()

    this._h = [
      0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
      0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ]

    this._zo = zo
    this._oo = oo
  }

  digest () {
    this._padding()

    const buffer = Buffer.alloc(28)
    for (let i = 0; i < 7; ++i) buffer.writeUInt32BE(this._h[i], i * 4)
    return buffer
  }
}

}).call(this,require("buffer").Buffer)
},{"./blake256":55,"buffer":62}],55:[function(require,module,exports){
(function (Buffer){
const Blake = require('./blake')

const zo = Buffer.from([0x01])
const oo = Buffer.from([0x81])

const rot = (x, n) => ((x << (32 - n)) | (x >>> n)) >>> 0

function g (v, m, i, a, b, c, d, e) {
  const sigma = Blake.sigma
  const u256 = Blake.u256

  v[a] = (v[a] + ((m[sigma[i][e]] ^ u256[sigma[i][e + 1]]) >>> 0) + v[b]) >>> 0
  v[d] = rot(v[d] ^ v[a], 16)
  v[c] = (v[c] + v[d]) >>> 0
  v[b] = rot(v[b] ^ v[c], 12)
  v[a] = (v[a] + ((m[sigma[i][e + 1]] ^ u256[sigma[i][e]]) >>> 0) + v[b]) >>> 0
  v[d] = rot(v[d] ^ v[a], 8)
  v[c] = (v[c] + v[d]) >>> 0
  v[b] = rot(v[b] ^ v[c], 7)
}

module.exports = class Blake256 extends Blake {
  constructor () {
    super()

    this._h = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    this._s = [0, 0, 0, 0]

    this._block = Buffer.alloc(64)
    this._blockOffset = 0
    this._length = [0, 0]

    this._nullt = false

    this._zo = zo
    this._oo = oo
  }

  _compress () {
    const u256 = Blake.u256
    const v = new Array(16)
    const m = new Array(16)
    let i

    for (i = 0; i < 16; ++i) m[i] = this._block.readUInt32BE(i * 4)
    for (i = 0; i < 8; ++i) v[i] = this._h[i] >>> 0
    for (i = 8; i < 12; ++i) v[i] = (this._s[i - 8] ^ u256[i - 8]) >>> 0
    for (i = 12; i < 16; ++i) v[i] = u256[i - 8]

    if (!this._nullt) {
      v[12] = (v[12] ^ this._length[0]) >>> 0
      v[13] = (v[13] ^ this._length[0]) >>> 0
      v[14] = (v[14] ^ this._length[1]) >>> 0
      v[15] = (v[15] ^ this._length[1]) >>> 0
    }

    for (i = 0; i < 14; ++i) {
      /* column step */
      g(v, m, i, 0, 4, 8, 12, 0)
      g(v, m, i, 1, 5, 9, 13, 2)
      g(v, m, i, 2, 6, 10, 14, 4)
      g(v, m, i, 3, 7, 11, 15, 6)
      /* diagonal step */
      g(v, m, i, 0, 5, 10, 15, 8)
      g(v, m, i, 1, 6, 11, 12, 10)
      g(v, m, i, 2, 7, 8, 13, 12)
      g(v, m, i, 3, 4, 9, 14, 14)
    }

    for (i = 0; i < 16; ++i) this._h[i % 8] = (this._h[i % 8] ^ v[i]) >>> 0
    for (i = 0; i < 8; ++i) this._h[i] = (this._h[i] ^ this._s[i % 4]) >>> 0
  }

  _padding () {
    let lo = this._length[0] + this._blockOffset * 8
    let hi = this._length[1]
    if (lo >= 0x0100000000) {
      lo -= 0x0100000000
      hi += 1
    }

    const msglen = Buffer.alloc(8)
    msglen.writeUInt32BE(hi, 0)
    msglen.writeUInt32BE(lo, 4)

    if (this._blockOffset === 55) {
      this._length[0] -= 8
      this.update(this._oo)
    } else {
      if (this._blockOffset < 55) {
        if (this._blockOffset === 0) this._nullt = true
        this._length[0] -= (55 - this._blockOffset) * 8
        this.update(Blake.padding.slice(0, 55 - this._blockOffset))
      } else {
        this._length[0] -= (64 - this._blockOffset) * 8
        this.update(Blake.padding.slice(0, 64 - this._blockOffset))
        this._length[0] -= 55 * 8
        this.update(Blake.padding.slice(1, 1 + 55))
        this._nullt = true
      }

      this.update(this._zo)
      this._length[0] -= 8
    }

    this._length[0] -= 64
    this.update(msglen)
  }

  digest () {
    this._padding()

    const buffer = Buffer.alloc(32)
    for (let i = 0; i < 8; ++i) buffer.writeUInt32BE(this._h[i], i * 4)
    return buffer
  }
}

}).call(this,require("buffer").Buffer)
},{"./blake":53,"buffer":62}],56:[function(require,module,exports){
(function (Buffer){
const Blake512 = require('./blake512')

const zo = Buffer.from([0x00])
const oo = Buffer.from([0x80])

module.exports = class Blake384 extends Blake512 {
  constructor () {
    super()

    this._h = [
      0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507,
      0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
      0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511,
      0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4
    ]

    this._zo = zo
    this._oo = oo
  }

  digest () {
    this._padding()

    const buffer = Buffer.alloc(48)
    for (let i = 0; i < 12; ++i) buffer.writeUInt32BE(this._h[i], i * 4)
    return buffer
  }
}

}).call(this,require("buffer").Buffer)
},{"./blake512":57,"buffer":62}],57:[function(require,module,exports){
(function (Buffer){
const Blake = require('./blake')

const zo = Buffer.from([0x01])
const oo = Buffer.from([0x81])

function rot (v, i, j, n) {
  let hi = v[i * 2] ^ v[j * 2]
  let lo = v[i * 2 + 1] ^ v[j * 2 + 1]

  if (n >= 32) {
    lo = lo ^ hi
    hi = lo ^ hi
    lo = lo ^ hi
    n -= 32
  }

  if (n === 0) {
    v[i * 2] = hi >>> 0
    v[i * 2 + 1] = lo >>> 0
  } else {
    v[i * 2] = ((hi >>> n) | (lo << (32 - n))) >>> 0
    v[i * 2 + 1] = ((lo >>> n) | (hi << (32 - n))) >>> 0
  }
}

function g (v, m, i, a, b, c, d, e) {
  const sigma = Blake.sigma
  const u512 = Blake.u512
  let lo

  // v[a] += (m[sigma[i][e]] ^ u512[sigma[i][e+1]]) + v[b];
  lo = v[a * 2 + 1] + ((m[sigma[i][e] * 2 + 1] ^ u512[sigma[i][e + 1] * 2 + 1]) >>> 0) + v[b * 2 + 1]
  v[a * 2] = (v[a * 2] + ((m[sigma[i][e] * 2] ^ u512[sigma[i][e + 1] * 2]) >>> 0) + v[b * 2] + ~~(lo / 0x0100000000)) >>> 0
  v[a * 2 + 1] = lo >>> 0

  // v[d] = ROT( v[d] ^ v[a],32);
  rot(v, d, a, 32)

  // v[c] += v[d];
  lo = v[c * 2 + 1] + v[d * 2 + 1]
  v[c * 2] = (v[c * 2] + v[d * 2] + ~~(lo / 0x0100000000)) >>> 0
  v[c * 2 + 1] = lo >>> 0

  // v[b] = ROT( v[b] ^ v[c],25);
  rot(v, b, c, 25)

  // v[a] += (m[sigma[i][e+1]] ^ u512[sigma[i][e]])+v[b];
  lo = v[a * 2 + 1] + ((m[sigma[i][e + 1] * 2 + 1] ^ u512[sigma[i][e] * 2 + 1]) >>> 0) + v[b * 2 + 1]
  v[a * 2] = (v[a * 2] + ((m[sigma[i][e + 1] * 2] ^ u512[sigma[i][e] * 2]) >>> 0) + v[b * 2] + ~~(lo / 0x0100000000)) >>> 0
  v[a * 2 + 1] = lo >>> 0

  // v[d] = ROT( v[d] ^ v[a],16);
  rot(v, d, a, 16)

  // v[c] += v[d];
  lo = v[c * 2 + 1] + v[d * 2 + 1]
  v[c * 2] = (v[c * 2] + v[d * 2] + ~~(lo / 0x0100000000)) >>> 0
  v[c * 2 + 1] = lo >>> 0

  // v[b] = ROT( v[b] ^ v[c],11)
  rot(v, b, c, 11)
}

module.exports = class Blake512 extends Blake {
  constructor () {
    super()

    this._h = [
      0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
      0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
      0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
      0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
    ]

    this._s = [0, 0, 0, 0, 0, 0, 0, 0]

    this._block = Buffer.alloc(128)
    this._blockOffset = 0
    this._length = [0, 0, 0, 0]

    this._nullt = false

    this._zo = zo
    this._oo = oo
  }

  _compress () {
    const u512 = Blake.u512
    const v = new Array(32)
    const m = new Array(32)
    let i

    for (i = 0; i < 32; ++i) m[i] = this._block.readUInt32BE(i * 4)
    for (i = 0; i < 16; ++i) v[i] = this._h[i] >>> 0
    for (i = 16; i < 24; ++i) v[i] = (this._s[i - 16] ^ u512[i - 16]) >>> 0
    for (i = 24; i < 32; ++i) v[i] = u512[i - 16]

    if (!this._nullt) {
      v[24] = (v[24] ^ this._length[1]) >>> 0
      v[25] = (v[25] ^ this._length[0]) >>> 0
      v[26] = (v[26] ^ this._length[1]) >>> 0
      v[27] = (v[27] ^ this._length[0]) >>> 0
      v[28] = (v[28] ^ this._length[3]) >>> 0
      v[29] = (v[29] ^ this._length[2]) >>> 0
      v[30] = (v[30] ^ this._length[3]) >>> 0
      v[31] = (v[31] ^ this._length[2]) >>> 0
    }

    for (i = 0; i < 16; ++i) {
      /* column step */
      g(v, m, i, 0, 4, 8, 12, 0)
      g(v, m, i, 1, 5, 9, 13, 2)
      g(v, m, i, 2, 6, 10, 14, 4)
      g(v, m, i, 3, 7, 11, 15, 6)
      /* diagonal step */
      g(v, m, i, 0, 5, 10, 15, 8)
      g(v, m, i, 1, 6, 11, 12, 10)
      g(v, m, i, 2, 7, 8, 13, 12)
      g(v, m, i, 3, 4, 9, 14, 14)
    }

    for (i = 0; i < 16; ++i) {
      this._h[(i % 8) * 2] = (this._h[(i % 8) * 2] ^ v[i * 2]) >>> 0
      this._h[(i % 8) * 2 + 1] = (this._h[(i % 8) * 2 + 1] ^ v[i * 2 + 1]) >>> 0
    }

    for (i = 0; i < 8; ++i) {
      this._h[i * 2] = (this._h[i * 2] ^ this._s[(i % 4) * 2]) >>> 0
      this._h[i * 2 + 1] = (this._h[i * 2 + 1] ^ this._s[(i % 4) * 2 + 1]) >>> 0
    }
  }

  _padding () {
    const len = this._length.slice()
    len[0] += this._blockOffset * 8
    this._lengthCarry(len)

    const msglen = Buffer.alloc(16)
    for (let i = 0; i < 4; ++i) msglen.writeUInt32BE(len[3 - i], i * 4)

    if (this._blockOffset === 111) {
      this._length[0] -= 8
      this.update(this._oo)
    } else {
      if (this._blockOffset < 111) {
        if (this._blockOffset === 0) this._nullt = true
        this._length[0] -= (111 - this._blockOffset) * 8
        this.update(Blake.padding.slice(0, 111 - this._blockOffset))
      } else {
        this._length[0] -= (128 - this._blockOffset) * 8
        this.update(Blake.padding.slice(0, 128 - this._blockOffset))
        this._length[0] -= 111 * 8
        this.update(Blake.padding.slice(1, 1 + 111))
        this._nullt = true
      }

      this.update(this._zo)
      this._length[0] -= 8
    }

    this._length[0] -= 128
    this.update(msglen)
  }

  digest () {
    this._padding()

    const buffer = Buffer.alloc(64)
    for (let i = 0; i < 16; ++i) buffer.writeUInt32BE(this._h[i], i * 4)
    return buffer
  }
}

}).call(this,require("buffer").Buffer)
},{"./blake":53,"buffer":62}],58:[function(require,module,exports){
module.exports = {
  Blake224: require('./blake224'),
  Blake256: require('./blake256'),
  Blake384: require('./blake384'),
  Blake512: require('./blake512')
}

},{"./blake224":54,"./blake256":55,"./blake384":56,"./blake512":57}],59:[function(require,module,exports){
(function (module, exports) {
  'use strict';

  // Utils
  function assert (val, msg) {
    if (!val) throw new Error(msg || 'Assertion failed');
  }

  // Could use `inherits` module, but don't want to move from single file
  // architecture yet.
  function inherits (ctor, superCtor) {
    ctor.super_ = superCtor;
    var TempCtor = function () {};
    TempCtor.prototype = superCtor.prototype;
    ctor.prototype = new TempCtor();
    ctor.prototype.constructor = ctor;
  }

  // BN

  function BN (number, base, endian) {
    if (BN.isBN(number)) {
      return number;
    }

    this.negative = 0;
    this.words = null;
    this.length = 0;

    // Reduction context
    this.red = null;

    if (number !== null) {
      if (base === 'le' || base === 'be') {
        endian = base;
        base = 10;
      }

      this._init(number || 0, base || 10, endian || 'be');
    }
  }
  if (typeof module === 'object') {
    module.exports = BN;
  } else {
    exports.BN = BN;
  }

  BN.BN = BN;
  BN.wordSize = 26;

  var Buffer;
  try {
    Buffer = require('buffer').Buffer;
  } catch (e) {
  }

  BN.isBN = function isBN (num) {
    if (num instanceof BN) {
      return true;
    }

    return num !== null && typeof num === 'object' &&
      num.constructor.wordSize === BN.wordSize && Array.isArray(num.words);
  };

  BN.max = function max (left, right) {
    if (left.cmp(right) > 0) return left;
    return right;
  };

  BN.min = function min (left, right) {
    if (left.cmp(right) < 0) return left;
    return right;
  };

  BN.prototype._init = function init (number, base, endian) {
    if (typeof number === 'number') {
      return this._initNumber(number, base, endian);
    }

    if (typeof number === 'object') {
      return this._initArray(number, base, endian);
    }

    if (base === 'hex') {
      base = 16;
    }
    assert(base === (base | 0) && base >= 2 && base <= 36);

    number = number.toString().replace(/\s+/g, '');
    var start = 0;
    if (number[0] === '-') {
      start++;
    }

    if (base === 16) {
      this._parseHex(number, start);
    } else {
      this._parseBase(number, base, start);
    }

    if (number[0] === '-') {
      this.negative = 1;
    }

    this._strip();

    if (endian !== 'le') return;

    this._initArray(this.toArray(), base, endian);
  };

  BN.prototype._initNumber = function _initNumber (number, base, endian) {
    if (number < 0) {
      this.negative = 1;
      number = -number;
    }
    if (number < 0x4000000) {
      this.words = [number & 0x3ffffff];
      this.length = 1;
    } else if (number < 0x10000000000000) {
      this.words = [
        number & 0x3ffffff,
        (number / 0x4000000) & 0x3ffffff
      ];
      this.length = 2;
    } else {
      assert(number < 0x20000000000000); // 2 ^ 53 (unsafe)
      this.words = [
        number & 0x3ffffff,
        (number / 0x4000000) & 0x3ffffff,
        1
      ];
      this.length = 3;
    }

    if (endian !== 'le') return;

    // Reverse the bytes
    this._initArray(this.toArray(), base, endian);
  };

  BN.prototype._initArray = function _initArray (number, base, endian) {
    // Perhaps a Uint8Array
    assert(typeof number.length === 'number');
    if (number.length <= 0) {
      this.words = [0];
      this.length = 1;
      return this;
    }

    this.length = Math.ceil(number.length / 3);
    this.words = new Array(this.length);
    for (var i = 0; i < this.length; i++) {
      this.words[i] = 0;
    }

    var j, w;
    var off = 0;
    if (endian === 'be') {
      for (i = number.length - 1, j = 0; i >= 0; i -= 3) {
        w = number[i] | (number[i - 1] << 8) | (number[i - 2] << 16);
        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
        off += 24;
        if (off >= 26) {
          off -= 26;
          j++;
        }
      }
    } else if (endian === 'le') {
      for (i = 0, j = 0; i < number.length; i += 3) {
        w = number[i] | (number[i + 1] << 8) | (number[i + 2] << 16);
        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
        off += 24;
        if (off >= 26) {
          off -= 26;
          j++;
        }
      }
    }
    return this._strip();
  };

  function parseHex (str, start, end) {
    var r = 0;
    var len = Math.min(str.length, end);
    var z = 0;
    for (var i = start; i < len; i++) {
      var c = str.charCodeAt(i) - 48;

      r <<= 4;

      var b;

      // 'a' - 'f'
      if (c >= 49 && c <= 54) {
        b = c - 49 + 0xa;

      // 'A' - 'F'
      } else if (c >= 17 && c <= 22) {
        b = c - 17 + 0xa;

      // '0' - '9'
      } else {
        b = c;
      }

      r |= b;
      z |= b;
    }

    assert(!(z & 0xf0), 'Invalid character in ' + str);
    return r;
  }

  BN.prototype._parseHex = function _parseHex (number, start) {
    // Create possibly bigger array to ensure that it fits the number
    this.length = Math.ceil((number.length - start) / 6);
    this.words = new Array(this.length);
    for (var i = 0; i < this.length; i++) {
      this.words[i] = 0;
    }

    var j, w;
    // Scan 24-bit chunks and add them to the number
    var off = 0;
    for (i = number.length - 6, j = 0; i >= start; i -= 6) {
      w = parseHex(number, i, i + 6);
      this.words[j] |= (w << off) & 0x3ffffff;
      // NOTE: `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;
      off += 24;
      if (off >= 26) {
        off -= 26;
        j++;
      }
    }
    if (i + 6 !== start) {
      w = parseHex(number, start, i + 6);
      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] |= w >>> (26 - off) & 0x3fffff;
    }
    this._strip();
  };

  function parseBase (str, start, end, mul) {
    var r = 0;
    var b = 0;
    var len = Math.min(str.length, end);
    for (var i = start; i < len; i++) {
      var c = str.charCodeAt(i) - 48;

      r *= mul;

      // 'a'
      if (c >= 49) {
        b = c - 49 + 0xa;

      // 'A'
      } else if (c >= 17) {
        b = c - 17 + 0xa;

      // '0' - '9'
      } else {
        b = c;
      }
      assert(c >= 0 && b < mul, 'Invalid character');
      r += b;
    }
    return r;
  }

  BN.prototype._parseBase = function _parseBase (number, base, start) {
    // Initialize as zero
    this.words = [0];
    this.length = 1;

    // Find length of limb in base
    for (var limbLen = 0, limbPow = 1; limbPow <= 0x3ffffff; limbPow *= base) {
      limbLen++;
    }
    limbLen--;
    limbPow = (limbPow / base) | 0;

    var total = number.length - start;
    var mod = total % limbLen;
    var end = Math.min(total, total - mod) + start;

    var word = 0;
    for (var i = start; i < end; i += limbLen) {
      word = parseBase(number, i, i + limbLen, base);

      this.imuln(limbPow);
      if (this.words[0] + word < 0x4000000) {
        this.words[0] += word;
      } else {
        this._iaddn(word);
      }
    }

    if (mod !== 0) {
      var pow = 1;
      word = parseBase(number, i, number.length, base);

      for (i = 0; i < mod; i++) {
        pow *= base;
      }

      this.imuln(pow);
      if (this.words[0] + word < 0x4000000) {
        this.words[0] += word;
      } else {
        this._iaddn(word);
      }
    }
  };

  BN.prototype.copy = function copy (dest) {
    dest.words = new Array(this.length);
    for (var i = 0; i < this.length; i++) {
      dest.words[i] = this.words[i];
    }
    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
  };

  function move (dest, src) {
    dest.words = src.words;
    dest.length = src.length;
    dest.negative = src.negative;
    dest.red = src.red;
  }

  BN.prototype._move = function _move (dest) {
    move(dest, this);
  };

  BN.prototype.clone = function clone () {
    var r = new BN(null);
    this.copy(r);
    return r;
  };

  BN.prototype._expand = function _expand (size) {
    while (this.length < size) {
      this.words[this.length++] = 0;
    }
    return this;
  };

  // Remove leading `0` from `this`
  BN.prototype._strip = function strip () {
    while (this.length > 1 && this.words[this.length - 1] === 0) {
      this.length--;
    }
    return this._normSign();
  };

  BN.prototype._normSign = function _normSign () {
    // -0 = 0
    if (this.length === 1 && this.words[0] === 0) {
      this.negative = 0;
    }
    return this;
  };

  // Check Symbol.for because not everywhere where Symbol defined
  // See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Symbol#Browser_compatibility
  if (typeof Symbol !== 'undefined' && typeof Symbol.for === 'function') {
    BN.prototype[Symbol.for('nodejs.util.inspect.custom')] = inspect;
  } else {
    BN.prototype.inspect = inspect;
  }

  function inspect () {
    return (this.red ? '<BN-R: ' : '<BN: ') + this.toString(16) + '>';
  }

  /*

  var zeros = [];
  var groupSizes = [];
  var groupBases = [];

  var s = '';
  var i = -1;
  while (++i < BN.wordSize) {
    zeros[i] = s;
    s += '0';
  }
  groupSizes[0] = 0;
  groupSizes[1] = 0;
  groupBases[0] = 0;
  groupBases[1] = 0;
  var base = 2 - 1;
  while (++base < 36 + 1) {
    var groupSize = 0;
    var groupBase = 1;
    while (groupBase < (1 << BN.wordSize) / base) {
      groupBase *= base;
      groupSize += 1;
    }
    groupSizes[base] = groupSize;
    groupBases[base] = groupBase;
  }

  */

  var zeros = [
    '',
    '0',
    '00',
    '000',
    '0000',
    '00000',
    '000000',
    '0000000',
    '00000000',
    '000000000',
    '0000000000',
    '00000000000',
    '000000000000',
    '0000000000000',
    '00000000000000',
    '000000000000000',
    '0000000000000000',
    '00000000000000000',
    '000000000000000000',
    '0000000000000000000',
    '00000000000000000000',
    '000000000000000000000',
    '0000000000000000000000',
    '00000000000000000000000',
    '000000000000000000000000',
    '0000000000000000000000000'
  ];

  var groupSizes = [
    0, 0,
    25, 16, 12, 11, 10, 9, 8,
    8, 7, 7, 7, 7, 6, 6,
    6, 6, 6, 6, 6, 5, 5,
    5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5
  ];

  var groupBases = [
    0, 0,
    33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216,
    43046721, 10000000, 19487171, 35831808, 62748517, 7529536, 11390625,
    16777216, 24137569, 34012224, 47045881, 64000000, 4084101, 5153632,
    6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149,
    24300000, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176
  ];

  BN.prototype.toString = function toString (base, padding) {
    base = base || 10;
    padding = padding | 0 || 1;

    var out;
    if (base === 16 || base === 'hex') {
      out = '';
      var off = 0;
      var carry = 0;
      for (var i = 0; i < this.length; i++) {
        var w = this.words[i];
        var word = (((w << off) | carry) & 0xffffff).toString(16);
        carry = (w >>> (24 - off)) & 0xffffff;
        if (carry !== 0 || i !== this.length - 1) {
          out = zeros[6 - word.length] + word + out;
        } else {
          out = word + out;
        }
        off += 2;
        if (off >= 26) {
          off -= 26;
          i--;
        }
      }
      if (carry !== 0) {
        out = carry.toString(16) + out;
      }
      while (out.length % padding !== 0) {
        out = '0' + out;
      }
      if (this.negative !== 0) {
        out = '-' + out;
      }
      return out;
    }

    if (base === (base | 0) && base >= 2 && base <= 36) {
      // var groupSize = Math.floor(BN.wordSize * Math.LN2 / Math.log(base));
      var groupSize = groupSizes[base];
      // var groupBase = Math.pow(base, groupSize);
      var groupBase = groupBases[base];
      out = '';
      var c = this.clone();
      c.negative = 0;
      while (!c.isZero()) {
        var r = c.modrn(groupBase).toString(base);
        c = c.idivn(groupBase);

        if (!c.isZero()) {
          out = zeros[groupSize - r.length] + r + out;
        } else {
          out = r + out;
        }
      }
      if (this.isZero()) {
        out = '0' + out;
      }
      while (out.length % padding !== 0) {
        out = '0' + out;
      }
      if (this.negative !== 0) {
        out = '-' + out;
      }
      return out;
    }

    assert(false, 'Base should be between 2 and 36');
  };

  BN.prototype.toNumber = function toNumber () {
    var ret = this.words[0];
    if (this.length === 2) {
      ret += this.words[1] * 0x4000000;
    } else if (this.length === 3 && this.words[2] === 0x01) {
      // NOTE: at this stage it is known that the top bit is set
      ret += 0x10000000000000 + (this.words[1] * 0x4000000);
    } else if (this.length > 2) {
      assert(false, 'Number can only safely store up to 53 bits');
    }
    return (this.negative !== 0) ? -ret : ret;
  };

  BN.prototype.toJSON = function toJSON () {
    return this.toString(16, 2);
  };

  if (Buffer) {
    BN.prototype.toBuffer = function toBuffer (endian, length) {
      return this.toArrayLike(Buffer, endian, length);
    };
  }

  BN.prototype.toArray = function toArray (endian, length) {
    return this.toArrayLike(Array, endian, length);
  };

  var allocate = function allocate (ArrayType, size) {
    if (ArrayType.allocUnsafe) {
      return ArrayType.allocUnsafe(size);
    }
    return new ArrayType(size);
  };

  BN.prototype.toArrayLike = function toArrayLike (ArrayType, endian, length) {
    this._strip();

    var byteLength = this.byteLength();
    var reqLength = length || Math.max(1, byteLength);
    assert(byteLength <= reqLength, 'byte array longer than desired length');
    assert(reqLength > 0, 'Requested array length <= 0');

    var res = allocate(ArrayType, reqLength);
    var postfix = endian === 'le' ? 'LE' : 'BE';
    this['_toArrayLike' + postfix](res, byteLength);
    return res;
  };

  BN.prototype._toArrayLikeLE = function _toArrayLikeLE (res, byteLength) {
    var position = 0;
    var carry = 0;

    for (var i = 0, shift = 0; i < this.length; i++) {
      var word = (this.words[i] << shift) | carry;

      res[position++] = word & 0xff;
      if (position < res.length) {
        res[position++] = (word >> 8) & 0xff;
      }
      if (position < res.length) {
        res[position++] = (word >> 16) & 0xff;
      }

      if (shift === 6) {
        if (position < res.length) {
          res[position++] = (word >> 24) & 0xff;
        }
        carry = 0;
        shift = 0;
      } else {
        carry = word >>> 24;
        shift += 2;
      }
    }

    if (position < res.length) {
      res[position++] = carry;

      while (position < res.length) {
        res[position++] = 0;
      }
    }
  };

  BN.prototype._toArrayLikeBE = function _toArrayLikeBE (res, byteLength) {
    var position = res.length - 1;
    var carry = 0;

    for (var i = 0, shift = 0; i < this.length; i++) {
      var word = (this.words[i] << shift) | carry;

      res[position--] = word & 0xff;
      if (position >= 0) {
        res[position--] = (word >> 8) & 0xff;
      }
      if (position >= 0) {
        res[position--] = (word >> 16) & 0xff;
      }

      if (shift === 6) {
        if (position >= 0) {
          res[position--] = (word >> 24) & 0xff;
        }
        carry = 0;
        shift = 0;
      } else {
        carry = word >>> 24;
        shift += 2;
      }
    }

    if (position >= 0) {
      res[position--] = carry;

      while (position >= 0) {
        res[position--] = 0;
      }
    }
  };

  if (Math.clz32) {
    BN.prototype._countBits = function _countBits (w) {
      return 32 - Math.clz32(w);
    };
  } else {
    BN.prototype._countBits = function _countBits (w) {
      var t = w;
      var r = 0;
      if (t >= 0x1000) {
        r += 13;
        t >>>= 13;
      }
      if (t >= 0x40) {
        r += 7;
        t >>>= 7;
      }
      if (t >= 0x8) {
        r += 4;
        t >>>= 4;
      }
      if (t >= 0x02) {
        r += 2;
        t >>>= 2;
      }
      return r + t;
    };
  }

  BN.prototype._zeroBits = function _zeroBits (w) {
    // Short-cut
    if (w === 0) return 26;

    var t = w;
    var r = 0;
    if ((t & 0x1fff) === 0) {
      r += 13;
      t >>>= 13;
    }
    if ((t & 0x7f) === 0) {
      r += 7;
      t >>>= 7;
    }
    if ((t & 0xf) === 0) {
      r += 4;
      t >>>= 4;
    }
    if ((t & 0x3) === 0) {
      r += 2;
      t >>>= 2;
    }
    if ((t & 0x1) === 0) {
      r++;
    }
    return r;
  };

  // Return number of used bits in a BN
  BN.prototype.bitLength = function bitLength () {
    var w = this.words[this.length - 1];
    var hi = this._countBits(w);
    return (this.length - 1) * 26 + hi;
  };

  function toBitArray (num) {
    var w = new Array(num.bitLength());

    for (var bit = 0; bit < w.length; bit++) {
      var off = (bit / 26) | 0;
      var wbit = bit % 26;

      w[bit] = (num.words[off] >>> wbit) & 0x01;
    }

    return w;
  }

  // Number of trailing zero bits
  BN.prototype.zeroBits = function zeroBits () {
    if (this.isZero()) return 0;

    var r = 0;
    for (var i = 0; i < this.length; i++) {
      var b = this._zeroBits(this.words[i]);
      r += b;
      if (b !== 26) break;
    }
    return r;
  };

  BN.prototype.byteLength = function byteLength () {
    return Math.ceil(this.bitLength() / 8);
  };

  BN.prototype.toTwos = function toTwos (width) {
    if (this.negative !== 0) {
      return this.abs().inotn(width).iaddn(1);
    }
    return this.clone();
  };

  BN.prototype.fromTwos = function fromTwos (width) {
    if (this.testn(width - 1)) {
      return this.notn(width).iaddn(1).ineg();
    }
    return this.clone();
  };

  BN.prototype.isNeg = function isNeg () {
    return this.negative !== 0;
  };

  // Return negative clone of `this`
  BN.prototype.neg = function neg () {
    return this.clone().ineg();
  };

  BN.prototype.ineg = function ineg () {
    if (!this.isZero()) {
      this.negative ^= 1;
    }

    return this;
  };

  // Or `num` with `this` in-place
  BN.prototype.iuor = function iuor (num) {
    while (this.length < num.length) {
      this.words[this.length++] = 0;
    }

    for (var i = 0; i < num.length; i++) {
      this.words[i] = this.words[i] | num.words[i];
    }

    return this._strip();
  };

  BN.prototype.ior = function ior (num) {
    assert((this.negative | num.negative) === 0);
    return this.iuor(num);
  };

  // Or `num` with `this`
  BN.prototype.or = function or (num) {
    if (this.length > num.length) return this.clone().ior(num);
    return num.clone().ior(this);
  };

  BN.prototype.uor = function uor (num) {
    if (this.length > num.length) return this.clone().iuor(num);
    return num.clone().iuor(this);
  };

  // And `num` with `this` in-place
  BN.prototype.iuand = function iuand (num) {
    // b = min-length(num, this)
    var b;
    if (this.length > num.length) {
      b = num;
    } else {
      b = this;
    }

    for (var i = 0; i < b.length; i++) {
      this.words[i] = this.words[i] & num.words[i];
    }

    this.length = b.length;

    return this._strip();
  };

  BN.prototype.iand = function iand (num) {
    assert((this.negative | num.negative) === 0);
    return this.iuand(num);
  };

  // And `num` with `this`
  BN.prototype.and = function and (num) {
    if (this.length > num.length) return this.clone().iand(num);
    return num.clone().iand(this);
  };

  BN.prototype.uand = function uand (num) {
    if (this.length > num.length) return this.clone().iuand(num);
    return num.clone().iuand(this);
  };

  // Xor `num` with `this` in-place
  BN.prototype.iuxor = function iuxor (num) {
    // a.length > b.length
    var a;
    var b;
    if (this.length > num.length) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    for (var i = 0; i < b.length; i++) {
      this.words[i] = a.words[i] ^ b.words[i];
    }

    if (this !== a) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    this.length = a.length;

    return this._strip();
  };

  BN.prototype.ixor = function ixor (num) {
    assert((this.negative | num.negative) === 0);
    return this.iuxor(num);
  };

  // Xor `num` with `this`
  BN.prototype.xor = function xor (num) {
    if (this.length > num.length) return this.clone().ixor(num);
    return num.clone().ixor(this);
  };

  BN.prototype.uxor = function uxor (num) {
    if (this.length > num.length) return this.clone().iuxor(num);
    return num.clone().iuxor(this);
  };

  // Not ``this`` with ``width`` bitwidth
  BN.prototype.inotn = function inotn (width) {
    assert(typeof width === 'number' && width >= 0);

    var bytesNeeded = Math.ceil(width / 26) | 0;
    var bitsLeft = width % 26;

    // Extend the buffer with leading zeroes
    this._expand(bytesNeeded);

    if (bitsLeft > 0) {
      bytesNeeded--;
    }

    // Handle complete words
    for (var i = 0; i < bytesNeeded; i++) {
      this.words[i] = ~this.words[i] & 0x3ffffff;
    }

    // Handle the residue
    if (bitsLeft > 0) {
      this.words[i] = ~this.words[i] & (0x3ffffff >> (26 - bitsLeft));
    }

    // And remove leading zeroes
    return this._strip();
  };

  BN.prototype.notn = function notn (width) {
    return this.clone().inotn(width);
  };

  // Set `bit` of `this`
  BN.prototype.setn = function setn (bit, val) {
    assert(typeof bit === 'number' && bit >= 0);

    var off = (bit / 26) | 0;
    var wbit = bit % 26;

    this._expand(off + 1);

    if (val) {
      this.words[off] = this.words[off] | (1 << wbit);
    } else {
      this.words[off] = this.words[off] & ~(1 << wbit);
    }

    return this._strip();
  };

  // Add `num` to `this` in-place
  BN.prototype.iadd = function iadd (num) {
    var r;

    // negative + positive
    if (this.negative !== 0 && num.negative === 0) {
      this.negative = 0;
      r = this.isub(num);
      this.negative ^= 1;
      return this._normSign();

    // positive + negative
    } else if (this.negative === 0 && num.negative !== 0) {
      num.negative = 0;
      r = this.isub(num);
      num.negative = 1;
      return r._normSign();
    }

    // a.length > b.length
    var a, b;
    if (this.length > num.length) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    var carry = 0;
    for (var i = 0; i < b.length; i++) {
      r = (a.words[i] | 0) + (b.words[i] | 0) + carry;
      this.words[i] = r & 0x3ffffff;
      carry = r >>> 26;
    }
    for (; carry !== 0 && i < a.length; i++) {
      r = (a.words[i] | 0) + carry;
      this.words[i] = r & 0x3ffffff;
      carry = r >>> 26;
    }

    this.length = a.length;
    if (carry !== 0) {
      this.words[this.length] = carry;
      this.length++;
    // Copy the rest of the words
    } else if (a !== this) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    return this;
  };

  // Add `num` to `this`
  BN.prototype.add = function add (num) {
    var res;
    if (num.negative !== 0 && this.negative === 0) {
      num.negative = 0;
      res = this.sub(num);
      num.negative ^= 1;
      return res;
    } else if (num.negative === 0 && this.negative !== 0) {
      this.negative = 0;
      res = num.sub(this);
      this.negative = 1;
      return res;
    }

    if (this.length > num.length) return this.clone().iadd(num);

    return num.clone().iadd(this);
  };

  // Subtract `num` from `this` in-place
  BN.prototype.isub = function isub (num) {
    // this - (-num) = this + num
    if (num.negative !== 0) {
      num.negative = 0;
      var r = this.iadd(num);
      num.negative = 1;
      return r._normSign();

    // -this - num = -(this + num)
    } else if (this.negative !== 0) {
      this.negative = 0;
      this.iadd(num);
      this.negative = 1;
      return this._normSign();
    }

    // At this point both numbers are positive
    var cmp = this.cmp(num);

    // Optimization - zeroify
    if (cmp === 0) {
      this.negative = 0;
      this.length = 1;
      this.words[0] = 0;
      return this;
    }

    // a > b
    var a, b;
    if (cmp > 0) {
      a = this;
      b = num;
    } else {
      a = num;
      b = this;
    }

    var carry = 0;
    for (var i = 0; i < b.length; i++) {
      r = (a.words[i] | 0) - (b.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }
    for (; carry !== 0 && i < a.length; i++) {
      r = (a.words[i] | 0) + carry;
      carry = r >> 26;
      this.words[i] = r & 0x3ffffff;
    }

    // Copy rest of the words
    if (carry === 0 && i < a.length && a !== this) {
      for (; i < a.length; i++) {
        this.words[i] = a.words[i];
      }
    }

    this.length = Math.max(this.length, i);

    if (a !== this) {
      this.negative = 1;
    }

    return this._strip();
  };

  // Subtract `num` from `this`
  BN.prototype.sub = function sub (num) {
    return this.clone().isub(num);
  };

  function smallMulTo (self, num, out) {
    out.negative = num.negative ^ self.negative;
    var len = (self.length + num.length) | 0;
    out.length = len;
    len = (len - 1) | 0;

    // Peel one iteration (compiler can't do it, because of code complexity)
    var a = self.words[0] | 0;
    var b = num.words[0] | 0;
    var r = a * b;

    var lo = r & 0x3ffffff;
    var carry = (r / 0x4000000) | 0;
    out.words[0] = lo;

    for (var k = 1; k < len; k++) {
      // Sum all words with the same `i + j = k` and accumulate `ncarry`,
      // note that ncarry could be >= 0x3ffffff
      var ncarry = carry >>> 26;
      var rword = carry & 0x3ffffff;
      var maxJ = Math.min(k, num.length - 1);
      for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
        var i = (k - j) | 0;
        a = self.words[i] | 0;
        b = num.words[j] | 0;
        r = a * b + rword;
        ncarry += (r / 0x4000000) | 0;
        rword = r & 0x3ffffff;
      }
      out.words[k] = rword | 0;
      carry = ncarry | 0;
    }
    if (carry !== 0) {
      out.words[k] = carry | 0;
    } else {
      out.length--;
    }

    return out._strip();
  }

  // TODO(indutny): it may be reasonable to omit it for users who don't need
  // to work with 256-bit numbers, otherwise it gives 20% improvement for 256-bit
  // multiplication (like elliptic secp256k1).
  var comb10MulTo = function comb10MulTo (self, num, out) {
    var a = self.words;
    var b = num.words;
    var o = out.words;
    var c = 0;
    var lo;
    var mid;
    var hi;
    var a0 = a[0] | 0;
    var al0 = a0 & 0x1fff;
    var ah0 = a0 >>> 13;
    var a1 = a[1] | 0;
    var al1 = a1 & 0x1fff;
    var ah1 = a1 >>> 13;
    var a2 = a[2] | 0;
    var al2 = a2 & 0x1fff;
    var ah2 = a2 >>> 13;
    var a3 = a[3] | 0;
    var al3 = a3 & 0x1fff;
    var ah3 = a3 >>> 13;
    var a4 = a[4] | 0;
    var al4 = a4 & 0x1fff;
    var ah4 = a4 >>> 13;
    var a5 = a[5] | 0;
    var al5 = a5 & 0x1fff;
    var ah5 = a5 >>> 13;
    var a6 = a[6] | 0;
    var al6 = a6 & 0x1fff;
    var ah6 = a6 >>> 13;
    var a7 = a[7] | 0;
    var al7 = a7 & 0x1fff;
    var ah7 = a7 >>> 13;
    var a8 = a[8] | 0;
    var al8 = a8 & 0x1fff;
    var ah8 = a8 >>> 13;
    var a9 = a[9] | 0;
    var al9 = a9 & 0x1fff;
    var ah9 = a9 >>> 13;
    var b0 = b[0] | 0;
    var bl0 = b0 & 0x1fff;
    var bh0 = b0 >>> 13;
    var b1 = b[1] | 0;
    var bl1 = b1 & 0x1fff;
    var bh1 = b1 >>> 13;
    var b2 = b[2] | 0;
    var bl2 = b2 & 0x1fff;
    var bh2 = b2 >>> 13;
    var b3 = b[3] | 0;
    var bl3 = b3 & 0x1fff;
    var bh3 = b3 >>> 13;
    var b4 = b[4] | 0;
    var bl4 = b4 & 0x1fff;
    var bh4 = b4 >>> 13;
    var b5 = b[5] | 0;
    var bl5 = b5 & 0x1fff;
    var bh5 = b5 >>> 13;
    var b6 = b[6] | 0;
    var bl6 = b6 & 0x1fff;
    var bh6 = b6 >>> 13;
    var b7 = b[7] | 0;
    var bl7 = b7 & 0x1fff;
    var bh7 = b7 >>> 13;
    var b8 = b[8] | 0;
    var bl8 = b8 & 0x1fff;
    var bh8 = b8 >>> 13;
    var b9 = b[9] | 0;
    var bl9 = b9 & 0x1fff;
    var bh9 = b9 >>> 13;

    out.negative = self.negative ^ num.negative;
    out.length = 19;
    /* k = 0 */
    lo = Math.imul(al0, bl0);
    mid = Math.imul(al0, bh0);
    mid = (mid + Math.imul(ah0, bl0)) | 0;
    hi = Math.imul(ah0, bh0);
    var w0 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w0 >>> 26)) | 0;
    w0 &= 0x3ffffff;
    /* k = 1 */
    lo = Math.imul(al1, bl0);
    mid = Math.imul(al1, bh0);
    mid = (mid + Math.imul(ah1, bl0)) | 0;
    hi = Math.imul(ah1, bh0);
    lo = (lo + Math.imul(al0, bl1)) | 0;
    mid = (mid + Math.imul(al0, bh1)) | 0;
    mid = (mid + Math.imul(ah0, bl1)) | 0;
    hi = (hi + Math.imul(ah0, bh1)) | 0;
    var w1 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w1 >>> 26)) | 0;
    w1 &= 0x3ffffff;
    /* k = 2 */
    lo = Math.imul(al2, bl0);
    mid = Math.imul(al2, bh0);
    mid = (mid + Math.imul(ah2, bl0)) | 0;
    hi = Math.imul(ah2, bh0);
    lo = (lo + Math.imul(al1, bl1)) | 0;
    mid = (mid + Math.imul(al1, bh1)) | 0;
    mid = (mid + Math.imul(ah1, bl1)) | 0;
    hi = (hi + Math.imul(ah1, bh1)) | 0;
    lo = (lo + Math.imul(al0, bl2)) | 0;
    mid = (mid + Math.imul(al0, bh2)) | 0;
    mid = (mid + Math.imul(ah0, bl2)) | 0;
    hi = (hi + Math.imul(ah0, bh2)) | 0;
    var w2 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w2 >>> 26)) | 0;
    w2 &= 0x3ffffff;
    /* k = 3 */
    lo = Math.imul(al3, bl0);
    mid = Math.imul(al3, bh0);
    mid = (mid + Math.imul(ah3, bl0)) | 0;
    hi = Math.imul(ah3, bh0);
    lo = (lo + Math.imul(al2, bl1)) | 0;
    mid = (mid + Math.imul(al2, bh1)) | 0;
    mid = (mid + Math.imul(ah2, bl1)) | 0;
    hi = (hi + Math.imul(ah2, bh1)) | 0;
    lo = (lo + Math.imul(al1, bl2)) | 0;
    mid = (mid + Math.imul(al1, bh2)) | 0;
    mid = (mid + Math.imul(ah1, bl2)) | 0;
    hi = (hi + Math.imul(ah1, bh2)) | 0;
    lo = (lo + Math.imul(al0, bl3)) | 0;
    mid = (mid + Math.imul(al0, bh3)) | 0;
    mid = (mid + Math.imul(ah0, bl3)) | 0;
    hi = (hi + Math.imul(ah0, bh3)) | 0;
    var w3 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w3 >>> 26)) | 0;
    w3 &= 0x3ffffff;
    /* k = 4 */
    lo = Math.imul(al4, bl0);
    mid = Math.imul(al4, bh0);
    mid = (mid + Math.imul(ah4, bl0)) | 0;
    hi = Math.imul(ah4, bh0);
    lo = (lo + Math.imul(al3, bl1)) | 0;
    mid = (mid + Math.imul(al3, bh1)) | 0;
    mid = (mid + Math.imul(ah3, bl1)) | 0;
    hi = (hi + Math.imul(ah3, bh1)) | 0;
    lo = (lo + Math.imul(al2, bl2)) | 0;
    mid = (mid + Math.imul(al2, bh2)) | 0;
    mid = (mid + Math.imul(ah2, bl2)) | 0;
    hi = (hi + Math.imul(ah2, bh2)) | 0;
    lo = (lo + Math.imul(al1, bl3)) | 0;
    mid = (mid + Math.imul(al1, bh3)) | 0;
    mid = (mid + Math.imul(ah1, bl3)) | 0;
    hi = (hi + Math.imul(ah1, bh3)) | 0;
    lo = (lo + Math.imul(al0, bl4)) | 0;
    mid = (mid + Math.imul(al0, bh4)) | 0;
    mid = (mid + Math.imul(ah0, bl4)) | 0;
    hi = (hi + Math.imul(ah0, bh4)) | 0;
    var w4 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w4 >>> 26)) | 0;
    w4 &= 0x3ffffff;
    /* k = 5 */
    lo = Math.imul(al5, bl0);
    mid = Math.imul(al5, bh0);
    mid = (mid + Math.imul(ah5, bl0)) | 0;
    hi = Math.imul(ah5, bh0);
    lo = (lo + Math.imul(al4, bl1)) | 0;
    mid = (mid + Math.imul(al4, bh1)) | 0;
    mid = (mid + Math.imul(ah4, bl1)) | 0;
    hi = (hi + Math.imul(ah4, bh1)) | 0;
    lo = (lo + Math.imul(al3, bl2)) | 0;
    mid = (mid + Math.imul(al3, bh2)) | 0;
    mid = (mid + Math.imul(ah3, bl2)) | 0;
    hi = (hi + Math.imul(ah3, bh2)) | 0;
    lo = (lo + Math.imul(al2, bl3)) | 0;
    mid = (mid + Math.imul(al2, bh3)) | 0;
    mid = (mid + Math.imul(ah2, bl3)) | 0;
    hi = (hi + Math.imul(ah2, bh3)) | 0;
    lo = (lo + Math.imul(al1, bl4)) | 0;
    mid = (mid + Math.imul(al1, bh4)) | 0;
    mid = (mid + Math.imul(ah1, bl4)) | 0;
    hi = (hi + Math.imul(ah1, bh4)) | 0;
    lo = (lo + Math.imul(al0, bl5)) | 0;
    mid = (mid + Math.imul(al0, bh5)) | 0;
    mid = (mid + Math.imul(ah0, bl5)) | 0;
    hi = (hi + Math.imul(ah0, bh5)) | 0;
    var w5 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w5 >>> 26)) | 0;
    w5 &= 0x3ffffff;
    /* k = 6 */
    lo = Math.imul(al6, bl0);
    mid = Math.imul(al6, bh0);
    mid = (mid + Math.imul(ah6, bl0)) | 0;
    hi = Math.imul(ah6, bh0);
    lo = (lo + Math.imul(al5, bl1)) | 0;
    mid = (mid + Math.imul(al5, bh1)) | 0;
    mid = (mid + Math.imul(ah5, bl1)) | 0;
    hi = (hi + Math.imul(ah5, bh1)) | 0;
    lo = (lo + Math.imul(al4, bl2)) | 0;
    mid = (mid + Math.imul(al4, bh2)) | 0;
    mid = (mid + Math.imul(ah4, bl2)) | 0;
    hi = (hi + Math.imul(ah4, bh2)) | 0;
    lo = (lo + Math.imul(al3, bl3)) | 0;
    mid = (mid + Math.imul(al3, bh3)) | 0;
    mid = (mid + Math.imul(ah3, bl3)) | 0;
    hi = (hi + Math.imul(ah3, bh3)) | 0;
    lo = (lo + Math.imul(al2, bl4)) | 0;
    mid = (mid + Math.imul(al2, bh4)) | 0;
    mid = (mid + Math.imul(ah2, bl4)) | 0;
    hi = (hi + Math.imul(ah2, bh4)) | 0;
    lo = (lo + Math.imul(al1, bl5)) | 0;
    mid = (mid + Math.imul(al1, bh5)) | 0;
    mid = (mid + Math.imul(ah1, bl5)) | 0;
    hi = (hi + Math.imul(ah1, bh5)) | 0;
    lo = (lo + Math.imul(al0, bl6)) | 0;
    mid = (mid + Math.imul(al0, bh6)) | 0;
    mid = (mid + Math.imul(ah0, bl6)) | 0;
    hi = (hi + Math.imul(ah0, bh6)) | 0;
    var w6 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w6 >>> 26)) | 0;
    w6 &= 0x3ffffff;
    /* k = 7 */
    lo = Math.imul(al7, bl0);
    mid = Math.imul(al7, bh0);
    mid = (mid + Math.imul(ah7, bl0)) | 0;
    hi = Math.imul(ah7, bh0);
    lo = (lo + Math.imul(al6, bl1)) | 0;
    mid = (mid + Math.imul(al6, bh1)) | 0;
    mid = (mid + Math.imul(ah6, bl1)) | 0;
    hi = (hi + Math.imul(ah6, bh1)) | 0;
    lo = (lo + Math.imul(al5, bl2)) | 0;
    mid = (mid + Math.imul(al5, bh2)) | 0;
    mid = (mid + Math.imul(ah5, bl2)) | 0;
    hi = (hi + Math.imul(ah5, bh2)) | 0;
    lo = (lo + Math.imul(al4, bl3)) | 0;
    mid = (mid + Math.imul(al4, bh3)) | 0;
    mid = (mid + Math.imul(ah4, bl3)) | 0;
    hi = (hi + Math.imul(ah4, bh3)) | 0;
    lo = (lo + Math.imul(al3, bl4)) | 0;
    mid = (mid + Math.imul(al3, bh4)) | 0;
    mid = (mid + Math.imul(ah3, bl4)) | 0;
    hi = (hi + Math.imul(ah3, bh4)) | 0;
    lo = (lo + Math.imul(al2, bl5)) | 0;
    mid = (mid + Math.imul(al2, bh5)) | 0;
    mid = (mid + Math.imul(ah2, bl5)) | 0;
    hi = (hi + Math.imul(ah2, bh5)) | 0;
    lo = (lo + Math.imul(al1, bl6)) | 0;
    mid = (mid + Math.imul(al1, bh6)) | 0;
    mid = (mid + Math.imul(ah1, bl6)) | 0;
    hi = (hi + Math.imul(ah1, bh6)) | 0;
    lo = (lo + Math.imul(al0, bl7)) | 0;
    mid = (mid + Math.imul(al0, bh7)) | 0;
    mid = (mid + Math.imul(ah0, bl7)) | 0;
    hi = (hi + Math.imul(ah0, bh7)) | 0;
    var w7 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w7 >>> 26)) | 0;
    w7 &= 0x3ffffff;
    /* k = 8 */
    lo = Math.imul(al8, bl0);
    mid = Math.imul(al8, bh0);
    mid = (mid + Math.imul(ah8, bl0)) | 0;
    hi = Math.imul(ah8, bh0);
    lo = (lo + Math.imul(al7, bl1)) | 0;
    mid = (mid + Math.imul(al7, bh1)) | 0;
    mid = (mid + Math.imul(ah7, bl1)) | 0;
    hi = (hi + Math.imul(ah7, bh1)) | 0;
    lo = (lo + Math.imul(al6, bl2)) | 0;
    mid = (mid + Math.imul(al6, bh2)) | 0;
    mid = (mid + Math.imul(ah6, bl2)) | 0;
    hi = (hi + Math.imul(ah6, bh2)) | 0;
    lo = (lo + Math.imul(al5, bl3)) | 0;
    mid = (mid + Math.imul(al5, bh3)) | 0;
    mid = (mid + Math.imul(ah5, bl3)) | 0;
    hi = (hi + Math.imul(ah5, bh3)) | 0;
    lo = (lo + Math.imul(al4, bl4)) | 0;
    mid = (mid + Math.imul(al4, bh4)) | 0;
    mid = (mid + Math.imul(ah4, bl4)) | 0;
    hi = (hi + Math.imul(ah4, bh4)) | 0;
    lo = (lo + Math.imul(al3, bl5)) | 0;
    mid = (mid + Math.imul(al3, bh5)) | 0;
    mid = (mid + Math.imul(ah3, bl5)) | 0;
    hi = (hi + Math.imul(ah3, bh5)) | 0;
    lo = (lo + Math.imul(al2, bl6)) | 0;
    mid = (mid + Math.imul(al2, bh6)) | 0;
    mid = (mid + Math.imul(ah2, bl6)) | 0;
    hi = (hi + Math.imul(ah2, bh6)) | 0;
    lo = (lo + Math.imul(al1, bl7)) | 0;
    mid = (mid + Math.imul(al1, bh7)) | 0;
    mid = (mid + Math.imul(ah1, bl7)) | 0;
    hi = (hi + Math.imul(ah1, bh7)) | 0;
    lo = (lo + Math.imul(al0, bl8)) | 0;
    mid = (mid + Math.imul(al0, bh8)) | 0;
    mid = (mid + Math.imul(ah0, bl8)) | 0;
    hi = (hi + Math.imul(ah0, bh8)) | 0;
    var w8 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w8 >>> 26)) | 0;
    w8 &= 0x3ffffff;
    /* k = 9 */
    lo = Math.imul(al9, bl0);
    mid = Math.imul(al9, bh0);
    mid = (mid + Math.imul(ah9, bl0)) | 0;
    hi = Math.imul(ah9, bh0);
    lo = (lo + Math.imul(al8, bl1)) | 0;
    mid = (mid + Math.imul(al8, bh1)) | 0;
    mid = (mid + Math.imul(ah8, bl1)) | 0;
    hi = (hi + Math.imul(ah8, bh1)) | 0;
    lo = (lo + Math.imul(al7, bl2)) | 0;
    mid = (mid + Math.imul(al7, bh2)) | 0;
    mid = (mid + Math.imul(ah7, bl2)) | 0;
    hi = (hi + Math.imul(ah7, bh2)) | 0;
    lo = (lo + Math.imul(al6, bl3)) | 0;
    mid = (mid + Math.imul(al6, bh3)) | 0;
    mid = (mid + Math.imul(ah6, bl3)) | 0;
    hi = (hi + Math.imul(ah6, bh3)) | 0;
    lo = (lo + Math.imul(al5, bl4)) | 0;
    mid = (mid + Math.imul(al5, bh4)) | 0;
    mid = (mid + Math.imul(ah5, bl4)) | 0;
    hi = (hi + Math.imul(ah5, bh4)) | 0;
    lo = (lo + Math.imul(al4, bl5)) | 0;
    mid = (mid + Math.imul(al4, bh5)) | 0;
    mid = (mid + Math.imul(ah4, bl5)) | 0;
    hi = (hi + Math.imul(ah4, bh5)) | 0;
    lo = (lo + Math.imul(al3, bl6)) | 0;
    mid = (mid + Math.imul(al3, bh6)) | 0;
    mid = (mid + Math.imul(ah3, bl6)) | 0;
    hi = (hi + Math.imul(ah3, bh6)) | 0;
    lo = (lo + Math.imul(al2, bl7)) | 0;
    mid = (mid + Math.imul(al2, bh7)) | 0;
    mid = (mid + Math.imul(ah2, bl7)) | 0;
    hi = (hi + Math.imul(ah2, bh7)) | 0;
    lo = (lo + Math.imul(al1, bl8)) | 0;
    mid = (mid + Math.imul(al1, bh8)) | 0;
    mid = (mid + Math.imul(ah1, bl8)) | 0;
    hi = (hi + Math.imul(ah1, bh8)) | 0;
    lo = (lo + Math.imul(al0, bl9)) | 0;
    mid = (mid + Math.imul(al0, bh9)) | 0;
    mid = (mid + Math.imul(ah0, bl9)) | 0;
    hi = (hi + Math.imul(ah0, bh9)) | 0;
    var w9 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w9 >>> 26)) | 0;
    w9 &= 0x3ffffff;
    /* k = 10 */
    lo = Math.imul(al9, bl1);
    mid = Math.imul(al9, bh1);
    mid = (mid + Math.imul(ah9, bl1)) | 0;
    hi = Math.imul(ah9, bh1);
    lo = (lo + Math.imul(al8, bl2)) | 0;
    mid = (mid + Math.imul(al8, bh2)) | 0;
    mid = (mid + Math.imul(ah8, bl2)) | 0;
    hi = (hi + Math.imul(ah8, bh2)) | 0;
    lo = (lo + Math.imul(al7, bl3)) | 0;
    mid = (mid + Math.imul(al7, bh3)) | 0;
    mid = (mid + Math.imul(ah7, bl3)) | 0;
    hi = (hi + Math.imul(ah7, bh3)) | 0;
    lo = (lo + Math.imul(al6, bl4)) | 0;
    mid = (mid + Math.imul(al6, bh4)) | 0;
    mid = (mid + Math.imul(ah6, bl4)) | 0;
    hi = (hi + Math.imul(ah6, bh4)) | 0;
    lo = (lo + Math.imul(al5, bl5)) | 0;
    mid = (mid + Math.imul(al5, bh5)) | 0;
    mid = (mid + Math.imul(ah5, bl5)) | 0;
    hi = (hi + Math.imul(ah5, bh5)) | 0;
    lo = (lo + Math.imul(al4, bl6)) | 0;
    mid = (mid + Math.imul(al4, bh6)) | 0;
    mid = (mid + Math.imul(ah4, bl6)) | 0;
    hi = (hi + Math.imul(ah4, bh6)) | 0;
    lo = (lo + Math.imul(al3, bl7)) | 0;
    mid = (mid + Math.imul(al3, bh7)) | 0;
    mid = (mid + Math.imul(ah3, bl7)) | 0;
    hi = (hi + Math.imul(ah3, bh7)) | 0;
    lo = (lo + Math.imul(al2, bl8)) | 0;
    mid = (mid + Math.imul(al2, bh8)) | 0;
    mid = (mid + Math.imul(ah2, bl8)) | 0;
    hi = (hi + Math.imul(ah2, bh8)) | 0;
    lo = (lo + Math.imul(al1, bl9)) | 0;
    mid = (mid + Math.imul(al1, bh9)) | 0;
    mid = (mid + Math.imul(ah1, bl9)) | 0;
    hi = (hi + Math.imul(ah1, bh9)) | 0;
    var w10 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w10 >>> 26)) | 0;
    w10 &= 0x3ffffff;
    /* k = 11 */
    lo = Math.imul(al9, bl2);
    mid = Math.imul(al9, bh2);
    mid = (mid + Math.imul(ah9, bl2)) | 0;
    hi = Math.imul(ah9, bh2);
    lo = (lo + Math.imul(al8, bl3)) | 0;
    mid = (mid + Math.imul(al8, bh3)) | 0;
    mid = (mid + Math.imul(ah8, bl3)) | 0;
    hi = (hi + Math.imul(ah8, bh3)) | 0;
    lo = (lo + Math.imul(al7, bl4)) | 0;
    mid = (mid + Math.imul(al7, bh4)) | 0;
    mid = (mid + Math.imul(ah7, bl4)) | 0;
    hi = (hi + Math.imul(ah7, bh4)) | 0;
    lo = (lo + Math.imul(al6, bl5)) | 0;
    mid = (mid + Math.imul(al6, bh5)) | 0;
    mid = (mid + Math.imul(ah6, bl5)) | 0;
    hi = (hi + Math.imul(ah6, bh5)) | 0;
    lo = (lo + Math.imul(al5, bl6)) | 0;
    mid = (mid + Math.imul(al5, bh6)) | 0;
    mid = (mid + Math.imul(ah5, bl6)) | 0;
    hi = (hi + Math.imul(ah5, bh6)) | 0;
    lo = (lo + Math.imul(al4, bl7)) | 0;
    mid = (mid + Math.imul(al4, bh7)) | 0;
    mid = (mid + Math.imul(ah4, bl7)) | 0;
    hi = (hi + Math.imul(ah4, bh7)) | 0;
    lo = (lo + Math.imul(al3, bl8)) | 0;
    mid = (mid + Math.imul(al3, bh8)) | 0;
    mid = (mid + Math.imul(ah3, bl8)) | 0;
    hi = (hi + Math.imul(ah3, bh8)) | 0;
    lo = (lo + Math.imul(al2, bl9)) | 0;
    mid = (mid + Math.imul(al2, bh9)) | 0;
    mid = (mid + Math.imul(ah2, bl9)) | 0;
    hi = (hi + Math.imul(ah2, bh9)) | 0;
    var w11 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w11 >>> 26)) | 0;
    w11 &= 0x3ffffff;
    /* k = 12 */
    lo = Math.imul(al9, bl3);
    mid = Math.imul(al9, bh3);
    mid = (mid + Math.imul(ah9, bl3)) | 0;
    hi = Math.imul(ah9, bh3);
    lo = (lo + Math.imul(al8, bl4)) | 0;
    mid = (mid + Math.imul(al8, bh4)) | 0;
    mid = (mid + Math.imul(ah8, bl4)) | 0;
    hi = (hi + Math.imul(ah8, bh4)) | 0;
    lo = (lo + Math.imul(al7, bl5)) | 0;
    mid = (mid + Math.imul(al7, bh5)) | 0;
    mid = (mid + Math.imul(ah7, bl5)) | 0;
    hi = (hi + Math.imul(ah7, bh5)) | 0;
    lo = (lo + Math.imul(al6, bl6)) | 0;
    mid = (mid + Math.imul(al6, bh6)) | 0;
    mid = (mid + Math.imul(ah6, bl6)) | 0;
    hi = (hi + Math.imul(ah6, bh6)) | 0;
    lo = (lo + Math.imul(al5, bl7)) | 0;
    mid = (mid + Math.imul(al5, bh7)) | 0;
    mid = (mid + Math.imul(ah5, bl7)) | 0;
    hi = (hi + Math.imul(ah5, bh7)) | 0;
    lo = (lo + Math.imul(al4, bl8)) | 0;
    mid = (mid + Math.imul(al4, bh8)) | 0;
    mid = (mid + Math.imul(ah4, bl8)) | 0;
    hi = (hi + Math.imul(ah4, bh8)) | 0;
    lo = (lo + Math.imul(al3, bl9)) | 0;
    mid = (mid + Math.imul(al3, bh9)) | 0;
    mid = (mid + Math.imul(ah3, bl9)) | 0;
    hi = (hi + Math.imul(ah3, bh9)) | 0;
    var w12 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w12 >>> 26)) | 0;
    w12 &= 0x3ffffff;
    /* k = 13 */
    lo = Math.imul(al9, bl4);
    mid = Math.imul(al9, bh4);
    mid = (mid + Math.imul(ah9, bl4)) | 0;
    hi = Math.imul(ah9, bh4);
    lo = (lo + Math.imul(al8, bl5)) | 0;
    mid = (mid + Math.imul(al8, bh5)) | 0;
    mid = (mid + Math.imul(ah8, bl5)) | 0;
    hi = (hi + Math.imul(ah8, bh5)) | 0;
    lo = (lo + Math.imul(al7, bl6)) | 0;
    mid = (mid + Math.imul(al7, bh6)) | 0;
    mid = (mid + Math.imul(ah7, bl6)) | 0;
    hi = (hi + Math.imul(ah7, bh6)) | 0;
    lo = (lo + Math.imul(al6, bl7)) | 0;
    mid = (mid + Math.imul(al6, bh7)) | 0;
    mid = (mid + Math.imul(ah6, bl7)) | 0;
    hi = (hi + Math.imul(ah6, bh7)) | 0;
    lo = (lo + Math.imul(al5, bl8)) | 0;
    mid = (mid + Math.imul(al5, bh8)) | 0;
    mid = (mid + Math.imul(ah5, bl8)) | 0;
    hi = (hi + Math.imul(ah5, bh8)) | 0;
    lo = (lo + Math.imul(al4, bl9)) | 0;
    mid = (mid + Math.imul(al4, bh9)) | 0;
    mid = (mid + Math.imul(ah4, bl9)) | 0;
    hi = (hi + Math.imul(ah4, bh9)) | 0;
    var w13 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w13 >>> 26)) | 0;
    w13 &= 0x3ffffff;
    /* k = 14 */
    lo = Math.imul(al9, bl5);
    mid = Math.imul(al9, bh5);
    mid = (mid + Math.imul(ah9, bl5)) | 0;
    hi = Math.imul(ah9, bh5);
    lo = (lo + Math.imul(al8, bl6)) | 0;
    mid = (mid + Math.imul(al8, bh6)) | 0;
    mid = (mid + Math.imul(ah8, bl6)) | 0;
    hi = (hi + Math.imul(ah8, bh6)) | 0;
    lo = (lo + Math.imul(al7, bl7)) | 0;
    mid = (mid + Math.imul(al7, bh7)) | 0;
    mid = (mid + Math.imul(ah7, bl7)) | 0;
    hi = (hi + Math.imul(ah7, bh7)) | 0;
    lo = (lo + Math.imul(al6, bl8)) | 0;
    mid = (mid + Math.imul(al6, bh8)) | 0;
    mid = (mid + Math.imul(ah6, bl8)) | 0;
    hi = (hi + Math.imul(ah6, bh8)) | 0;
    lo = (lo + Math.imul(al5, bl9)) | 0;
    mid = (mid + Math.imul(al5, bh9)) | 0;
    mid = (mid + Math.imul(ah5, bl9)) | 0;
    hi = (hi + Math.imul(ah5, bh9)) | 0;
    var w14 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w14 >>> 26)) | 0;
    w14 &= 0x3ffffff;
    /* k = 15 */
    lo = Math.imul(al9, bl6);
    mid = Math.imul(al9, bh6);
    mid = (mid + Math.imul(ah9, bl6)) | 0;
    hi = Math.imul(ah9, bh6);
    lo = (lo + Math.imul(al8, bl7)) | 0;
    mid = (mid + Math.imul(al8, bh7)) | 0;
    mid = (mid + Math.imul(ah8, bl7)) | 0;
    hi = (hi + Math.imul(ah8, bh7)) | 0;
    lo = (lo + Math.imul(al7, bl8)) | 0;
    mid = (mid + Math.imul(al7, bh8)) | 0;
    mid = (mid + Math.imul(ah7, bl8)) | 0;
    hi = (hi + Math.imul(ah7, bh8)) | 0;
    lo = (lo + Math.imul(al6, bl9)) | 0;
    mid = (mid + Math.imul(al6, bh9)) | 0;
    mid = (mid + Math.imul(ah6, bl9)) | 0;
    hi = (hi + Math.imul(ah6, bh9)) | 0;
    var w15 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w15 >>> 26)) | 0;
    w15 &= 0x3ffffff;
    /* k = 16 */
    lo = Math.imul(al9, bl7);
    mid = Math.imul(al9, bh7);
    mid = (mid + Math.imul(ah9, bl7)) | 0;
    hi = Math.imul(ah9, bh7);
    lo = (lo + Math.imul(al8, bl8)) | 0;
    mid = (mid + Math.imul(al8, bh8)) | 0;
    mid = (mid + Math.imul(ah8, bl8)) | 0;
    hi = (hi + Math.imul(ah8, bh8)) | 0;
    lo = (lo + Math.imul(al7, bl9)) | 0;
    mid = (mid + Math.imul(al7, bh9)) | 0;
    mid = (mid + Math.imul(ah7, bl9)) | 0;
    hi = (hi + Math.imul(ah7, bh9)) | 0;
    var w16 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w16 >>> 26)) | 0;
    w16 &= 0x3ffffff;
    /* k = 17 */
    lo = Math.imul(al9, bl8);
    mid = Math.imul(al9, bh8);
    mid = (mid + Math.imul(ah9, bl8)) | 0;
    hi = Math.imul(ah9, bh8);
    lo = (lo + Math.imul(al8, bl9)) | 0;
    mid = (mid + Math.imul(al8, bh9)) | 0;
    mid = (mid + Math.imul(ah8, bl9)) | 0;
    hi = (hi + Math.imul(ah8, bh9)) | 0;
    var w17 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w17 >>> 26)) | 0;
    w17 &= 0x3ffffff;
    /* k = 18 */
    lo = Math.imul(al9, bl9);
    mid = Math.imul(al9, bh9);
    mid = (mid + Math.imul(ah9, bl9)) | 0;
    hi = Math.imul(ah9, bh9);
    var w18 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
    c = (((hi + (mid >>> 13)) | 0) + (w18 >>> 26)) | 0;
    w18 &= 0x3ffffff;
    o[0] = w0;
    o[1] = w1;
    o[2] = w2;
    o[3] = w3;
    o[4] = w4;
    o[5] = w5;
    o[6] = w6;
    o[7] = w7;
    o[8] = w8;
    o[9] = w9;
    o[10] = w10;
    o[11] = w11;
    o[12] = w12;
    o[13] = w13;
    o[14] = w14;
    o[15] = w15;
    o[16] = w16;
    o[17] = w17;
    o[18] = w18;
    if (c !== 0) {
      o[19] = c;
      out.length++;
    }
    return out;
  };

  // Polyfill comb
  if (!Math.imul) {
    comb10MulTo = smallMulTo;
  }

  function bigMulTo (self, num, out) {
    out.negative = num.negative ^ self.negative;
    out.length = self.length + num.length;

    var carry = 0;
    var hncarry = 0;
    for (var k = 0; k < out.length - 1; k++) {
      // Sum all words with the same `i + j = k` and accumulate `ncarry`,
      // note that ncarry could be >= 0x3ffffff
      var ncarry = hncarry;
      hncarry = 0;
      var rword = carry & 0x3ffffff;
      var maxJ = Math.min(k, num.length - 1);
      for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
        var i = k - j;
        var a = self.words[i] | 0;
        var b = num.words[j] | 0;
        var r = a * b;

        var lo = r & 0x3ffffff;
        ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
        lo = (lo + rword) | 0;
        rword = lo & 0x3ffffff;
        ncarry = (ncarry + (lo >>> 26)) | 0;

        hncarry += ncarry >>> 26;
        ncarry &= 0x3ffffff;
      }
      out.words[k] = rword;
      carry = ncarry;
      ncarry = hncarry;
    }
    if (carry !== 0) {
      out.words[k] = carry;
    } else {
      out.length--;
    }

    return out._strip();
  }

  function jumboMulTo (self, num, out) {
    // Temporary disable, see https://github.com/indutny/bn.js/issues/211
    // var fftm = new FFTM();
    // return fftm.mulp(self, num, out);
    return bigMulTo(self, num, out);
  }

  BN.prototype.mulTo = function mulTo (num, out) {
    var res;
    var len = this.length + num.length;
    if (this.length === 10 && num.length === 10) {
      res = comb10MulTo(this, num, out);
    } else if (len < 63) {
      res = smallMulTo(this, num, out);
    } else if (len < 1024) {
      res = bigMulTo(this, num, out);
    } else {
      res = jumboMulTo(this, num, out);
    }

    return res;
  };

  // Cooley-Tukey algorithm for FFT
  // slightly revisited to rely on looping instead of recursion

  function FFTM (x, y) {
    this.x = x;
    this.y = y;
  }

  FFTM.prototype.makeRBT = function makeRBT (N) {
    var t = new Array(N);
    var l = BN.prototype._countBits(N) - 1;
    for (var i = 0; i < N; i++) {
      t[i] = this.revBin(i, l, N);
    }

    return t;
  };

  // Returns binary-reversed representation of `x`
  FFTM.prototype.revBin = function revBin (x, l, N) {
    if (x === 0 || x === N - 1) return x;

    var rb = 0;
    for (var i = 0; i < l; i++) {
      rb |= (x & 1) << (l - i - 1);
      x >>= 1;
    }

    return rb;
  };

  // Performs "tweedling" phase, therefore 'emulating'
  // behaviour of the recursive algorithm
  FFTM.prototype.permute = function permute (rbt, rws, iws, rtws, itws, N) {
    for (var i = 0; i < N; i++) {
      rtws[i] = rws[rbt[i]];
      itws[i] = iws[rbt[i]];
    }
  };

  FFTM.prototype.transform = function transform (rws, iws, rtws, itws, N, rbt) {
    this.permute(rbt, rws, iws, rtws, itws, N);

    for (var s = 1; s < N; s <<= 1) {
      var l = s << 1;

      var rtwdf = Math.cos(2 * Math.PI / l);
      var itwdf = Math.sin(2 * Math.PI / l);

      for (var p = 0; p < N; p += l) {
        var rtwdf_ = rtwdf;
        var itwdf_ = itwdf;

        for (var j = 0; j < s; j++) {
          var re = rtws[p + j];
          var ie = itws[p + j];

          var ro = rtws[p + j + s];
          var io = itws[p + j + s];

          var rx = rtwdf_ * ro - itwdf_ * io;

          io = rtwdf_ * io + itwdf_ * ro;
          ro = rx;

          rtws[p + j] = re + ro;
          itws[p + j] = ie + io;

          rtws[p + j + s] = re - ro;
          itws[p + j + s] = ie - io;

          /* jshint maxdepth : false */
          if (j !== l) {
            rx = rtwdf * rtwdf_ - itwdf * itwdf_;

            itwdf_ = rtwdf * itwdf_ + itwdf * rtwdf_;
            rtwdf_ = rx;
          }
        }
      }
    }
  };

  FFTM.prototype.guessLen13b = function guessLen13b (n, m) {
    var N = Math.max(m, n) | 1;
    var odd = N & 1;
    var i = 0;
    for (N = N / 2 | 0; N; N = N >>> 1) {
      i++;
    }

    return 1 << i + 1 + odd;
  };

  FFTM.prototype.conjugate = function conjugate (rws, iws, N) {
    if (N <= 1) return;

    for (var i = 0; i < N / 2; i++) {
      var t = rws[i];

      rws[i] = rws[N - i - 1];
      rws[N - i - 1] = t;

      t = iws[i];

      iws[i] = -iws[N - i - 1];
      iws[N - i - 1] = -t;
    }
  };

  FFTM.prototype.normalize13b = function normalize13b (ws, N) {
    var carry = 0;
    for (var i = 0; i < N / 2; i++) {
      var w = Math.round(ws[2 * i + 1] / N) * 0x2000 +
        Math.round(ws[2 * i] / N) +
        carry;

      ws[i] = w & 0x3ffffff;

      if (w < 0x4000000) {
        carry = 0;
      } else {
        carry = w / 0x4000000 | 0;
      }
    }

    return ws;
  };

  FFTM.prototype.convert13b = function convert13b (ws, len, rws, N) {
    var carry = 0;
    for (var i = 0; i < len; i++) {
      carry = carry + (ws[i] | 0);

      rws[2 * i] = carry & 0x1fff; carry = carry >>> 13;
      rws[2 * i + 1] = carry & 0x1fff; carry = carry >>> 13;
    }

    // Pad with zeroes
    for (i = 2 * len; i < N; ++i) {
      rws[i] = 0;
    }

    assert(carry === 0);
    assert((carry & ~0x1fff) === 0);
  };

  FFTM.prototype.stub = function stub (N) {
    var ph = new Array(N);
    for (var i = 0; i < N; i++) {
      ph[i] = 0;
    }

    return ph;
  };

  FFTM.prototype.mulp = function mulp (x, y, out) {
    var N = 2 * this.guessLen13b(x.length, y.length);

    var rbt = this.makeRBT(N);

    var _ = this.stub(N);

    var rws = new Array(N);
    var rwst = new Array(N);
    var iwst = new Array(N);

    var nrws = new Array(N);
    var nrwst = new Array(N);
    var niwst = new Array(N);

    var rmws = out.words;
    rmws.length = N;

    this.convert13b(x.words, x.length, rws, N);
    this.convert13b(y.words, y.length, nrws, N);

    this.transform(rws, _, rwst, iwst, N, rbt);
    this.transform(nrws, _, nrwst, niwst, N, rbt);

    for (var i = 0; i < N; i++) {
      var rx = rwst[i] * nrwst[i] - iwst[i] * niwst[i];
      iwst[i] = rwst[i] * niwst[i] + iwst[i] * nrwst[i];
      rwst[i] = rx;
    }

    this.conjugate(rwst, iwst, N);
    this.transform(rwst, iwst, rmws, _, N, rbt);
    this.conjugate(rmws, _, N);
    this.normalize13b(rmws, N);

    out.negative = x.negative ^ y.negative;
    out.length = x.length + y.length;
    return out._strip();
  };

  // Multiply `this` by `num`
  BN.prototype.mul = function mul (num) {
    var out = new BN(null);
    out.words = new Array(this.length + num.length);
    return this.mulTo(num, out);
  };

  // Multiply employing FFT
  BN.prototype.mulf = function mulf (num) {
    var out = new BN(null);
    out.words = new Array(this.length + num.length);
    return jumboMulTo(this, num, out);
  };

  // In-place Multiplication
  BN.prototype.imul = function imul (num) {
    return this.clone().mulTo(num, this);
  };

  BN.prototype.imuln = function imuln (num) {
    var isNegNum = num < 0;
    if (isNegNum) num = -num;

    assert(typeof num === 'number');
    assert(num < 0x4000000);

    // Carry
    var carry = 0;
    for (var i = 0; i < this.length; i++) {
      var w = (this.words[i] | 0) * num;
      var lo = (w & 0x3ffffff) + (carry & 0x3ffffff);
      carry >>= 26;
      carry += (w / 0x4000000) | 0;
      // NOTE: lo is 27bit maximum
      carry += lo >>> 26;
      this.words[i] = lo & 0x3ffffff;
    }

    if (carry !== 0) {
      this.words[i] = carry;
      this.length++;
    }

    return isNegNum ? this.ineg() : this;
  };

  BN.prototype.muln = function muln (num) {
    return this.clone().imuln(num);
  };

  // `this` * `this`
  BN.prototype.sqr = function sqr () {
    return this.mul(this);
  };

  // `this` * `this` in-place
  BN.prototype.isqr = function isqr () {
    return this.imul(this.clone());
  };

  // Math.pow(`this`, `num`)
  BN.prototype.pow = function pow (num) {
    var w = toBitArray(num);
    if (w.length === 0) return new BN(1);

    // Skip leading zeroes
    var res = this;
    for (var i = 0; i < w.length; i++, res = res.sqr()) {
      if (w[i] !== 0) break;
    }

    if (++i < w.length) {
      for (var q = res.sqr(); i < w.length; i++, q = q.sqr()) {
        if (w[i] === 0) continue;

        res = res.mul(q);
      }
    }

    return res;
  };

  // Shift-left in-place
  BN.prototype.iushln = function iushln (bits) {
    assert(typeof bits === 'number' && bits >= 0);
    var r = bits % 26;
    var s = (bits - r) / 26;
    var carryMask = (0x3ffffff >>> (26 - r)) << (26 - r);
    var i;

    if (r !== 0) {
      var carry = 0;

      for (i = 0; i < this.length; i++) {
        var newCarry = this.words[i] & carryMask;
        var c = ((this.words[i] | 0) - newCarry) << r;
        this.words[i] = c | carry;
        carry = newCarry >>> (26 - r);
      }

      if (carry) {
        this.words[i] = carry;
        this.length++;
      }
    }

    if (s !== 0) {
      for (i = this.length - 1; i >= 0; i--) {
        this.words[i + s] = this.words[i];
      }

      for (i = 0; i < s; i++) {
        this.words[i] = 0;
      }

      this.length += s;
    }

    return this._strip();
  };

  BN.prototype.ishln = function ishln (bits) {
    // TODO(indutny): implement me
    assert(this.negative === 0);
    return this.iushln(bits);
  };

  // Shift-right in-place
  // NOTE: `hint` is a lowest bit before trailing zeroes
  // NOTE: if `extended` is present - it will be filled with destroyed bits
  BN.prototype.iushrn = function iushrn (bits, hint, extended) {
    assert(typeof bits === 'number' && bits >= 0);
    var h;
    if (hint) {
      h = (hint - (hint % 26)) / 26;
    } else {
      h = 0;
    }

    var r = bits % 26;
    var s = Math.min((bits - r) / 26, this.length);
    var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
    var maskedWords = extended;

    h -= s;
    h = Math.max(0, h);

    // Extended mode, copy masked part
    if (maskedWords) {
      for (var i = 0; i < s; i++) {
        maskedWords.words[i] = this.words[i];
      }
      maskedWords.length = s;
    }

    if (s === 0) {
      // No-op, we should not move anything at all
    } else if (this.length > s) {
      this.length -= s;
      for (i = 0; i < this.length; i++) {
        this.words[i] = this.words[i + s];
      }
    } else {
      this.words[0] = 0;
      this.length = 1;
    }

    var carry = 0;
    for (i = this.length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
      var word = this.words[i] | 0;
      this.words[i] = (carry << (26 - r)) | (word >>> r);
      carry = word & mask;
    }

    // Push carried bits as a mask
    if (maskedWords && carry !== 0) {
      maskedWords.words[maskedWords.length++] = carry;
    }

    if (this.length === 0) {
      this.words[0] = 0;
      this.length = 1;
    }

    return this._strip();
  };

  BN.prototype.ishrn = function ishrn (bits, hint, extended) {
    // TODO(indutny): implement me
    assert(this.negative === 0);
    return this.iushrn(bits, hint, extended);
  };

  // Shift-left
  BN.prototype.shln = function shln (bits) {
    return this.clone().ishln(bits);
  };

  BN.prototype.ushln = function ushln (bits) {
    return this.clone().iushln(bits);
  };

  // Shift-right
  BN.prototype.shrn = function shrn (bits) {
    return this.clone().ishrn(bits);
  };

  BN.prototype.ushrn = function ushrn (bits) {
    return this.clone().iushrn(bits);
  };

  // Test if n bit is set
  BN.prototype.testn = function testn (bit) {
    assert(typeof bit === 'number' && bit >= 0);
    var r = bit % 26;
    var s = (bit - r) / 26;
    var q = 1 << r;

    // Fast case: bit is much higher than all existing words
    if (this.length <= s) return false;

    // Check bit and return
    var w = this.words[s];

    return !!(w & q);
  };

  // Return only lowers bits of number (in-place)
  BN.prototype.imaskn = function imaskn (bits) {
    assert(typeof bits === 'number' && bits >= 0);
    var r = bits % 26;
    var s = (bits - r) / 26;

    assert(this.negative === 0, 'imaskn works only with positive numbers');

    if (this.length <= s) {
      return this;
    }

    if (r !== 0) {
      s++;
    }
    this.length = Math.min(s, this.length);

    if (r !== 0) {
      var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
      this.words[this.length - 1] &= mask;
    }

    return this._strip();
  };

  // Return only lowers bits of number
  BN.prototype.maskn = function maskn (bits) {
    return this.clone().imaskn(bits);
  };

  // Add plain number `num` to `this`
  BN.prototype.iaddn = function iaddn (num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);
    if (num < 0) return this.isubn(-num);

    // Possible sign change
    if (this.negative !== 0) {
      if (this.length === 1 && (this.words[0] | 0) <= num) {
        this.words[0] = num - (this.words[0] | 0);
        this.negative = 0;
        return this;
      }

      this.negative = 0;
      this.isubn(num);
      this.negative = 1;
      return this;
    }

    // Add without checks
    return this._iaddn(num);
  };

  BN.prototype._iaddn = function _iaddn (num) {
    this.words[0] += num;

    // Carry
    for (var i = 0; i < this.length && this.words[i] >= 0x4000000; i++) {
      this.words[i] -= 0x4000000;
      if (i === this.length - 1) {
        this.words[i + 1] = 1;
      } else {
        this.words[i + 1]++;
      }
    }
    this.length = Math.max(this.length, i + 1);

    return this;
  };

  // Subtract plain number `num` from `this`
  BN.prototype.isubn = function isubn (num) {
    assert(typeof num === 'number');
    assert(num < 0x4000000);
    if (num < 0) return this.iaddn(-num);

    if (this.negative !== 0) {
      this.negative = 0;
      this.iaddn(num);
      this.negative = 1;
      return this;
    }

    this.words[0] -= num;

    if (this.length === 1 && this.words[0] < 0) {
      this.words[0] = -this.words[0];
      this.negative = 1;
    } else {
      // Carry
      for (var i = 0; i < this.length && this.words[i] < 0; i++) {
        this.words[i] += 0x4000000;
        this.words[i + 1] -= 1;
      }
    }

    return this._strip();
  };

  BN.prototype.addn = function addn (num) {
    return this.clone().iaddn(num);
  };

  BN.prototype.subn = function subn (num) {
    return this.clone().isubn(num);
  };

  BN.prototype.iabs = function iabs () {
    this.negative = 0;

    return this;
  };

  BN.prototype.abs = function abs () {
    return this.clone().iabs();
  };

  BN.prototype._ishlnsubmul = function _ishlnsubmul (num, mul, shift) {
    var len = num.length + shift;
    var i;

    this._expand(len);

    var w;
    var carry = 0;
    for (i = 0; i < num.length; i++) {
      w = (this.words[i + shift] | 0) + carry;
      var right = (num.words[i] | 0) * mul;
      w -= right & 0x3ffffff;
      carry = (w >> 26) - ((right / 0x4000000) | 0);
      this.words[i + shift] = w & 0x3ffffff;
    }
    for (; i < this.length - shift; i++) {
      w = (this.words[i + shift] | 0) + carry;
      carry = w >> 26;
      this.words[i + shift] = w & 0x3ffffff;
    }

    if (carry === 0) return this._strip();

    // Subtraction overflow
    assert(carry === -1);
    carry = 0;
    for (i = 0; i < this.length; i++) {
      w = -(this.words[i] | 0) + carry;
      carry = w >> 26;
      this.words[i] = w & 0x3ffffff;
    }
    this.negative = 1;

    return this._strip();
  };

  BN.prototype._wordDiv = function _wordDiv (num, mode) {
    var shift = this.length - num.length;

    var a = this.clone();
    var b = num;

    // Normalize
    var bhi = b.words[b.length - 1] | 0;
    var bhiBits = this._countBits(bhi);
    shift = 26 - bhiBits;
    if (shift !== 0) {
      b = b.ushln(shift);
      a.iushln(shift);
      bhi = b.words[b.length - 1] | 0;
    }

    // Initialize quotient
    var m = a.length - b.length;
    var q;

    if (mode !== 'mod') {
      q = new BN(null);
      q.length = m + 1;
      q.words = new Array(q.length);
      for (var i = 0; i < q.length; i++) {
        q.words[i] = 0;
      }
    }

    var diff = a.clone()._ishlnsubmul(b, 1, m);
    if (diff.negative === 0) {
      a = diff;
      if (q) {
        q.words[m] = 1;
      }
    }

    for (var j = m - 1; j >= 0; j--) {
      var qj = (a.words[b.length + j] | 0) * 0x4000000 +
        (a.words[b.length + j - 1] | 0);

      // NOTE: (qj / bhi) is (0x3ffffff * 0x4000000 + 0x3ffffff) / 0x2000000 max
      // (0x7ffffff)
      qj = Math.min((qj / bhi) | 0, 0x3ffffff);

      a._ishlnsubmul(b, qj, j);
      while (a.negative !== 0) {
        qj--;
        a.negative = 0;
        a._ishlnsubmul(b, 1, j);
        if (!a.isZero()) {
          a.negative ^= 1;
        }
      }
      if (q) {
        q.words[j] = qj;
      }
    }
    if (q) {
      q._strip();
    }
    a._strip();

    // Denormalize
    if (mode !== 'div' && shift !== 0) {
      a.iushrn(shift);
    }

    return {
      div: q || null,
      mod: a
    };
  };

  // NOTE: 1) `mode` can be set to `mod` to request mod only,
  //       to `div` to request div only, or be absent to
  //       request both div & mod
  //       2) `positive` is true if unsigned mod is requested
  BN.prototype.divmod = function divmod (num, mode, positive) {
    assert(!num.isZero());

    if (this.isZero()) {
      return {
        div: new BN(0),
        mod: new BN(0)
      };
    }

    var div, mod, res;
    if (this.negative !== 0 && num.negative === 0) {
      res = this.neg().divmod(num, mode);

      if (mode !== 'mod') {
        div = res.div.neg();
      }

      if (mode !== 'div') {
        mod = res.mod.neg();
        if (positive && mod.negative !== 0) {
          mod.iadd(num);
        }
      }

      return {
        div: div,
        mod: mod
      };
    }

    if (this.negative === 0 && num.negative !== 0) {
      res = this.divmod(num.neg(), mode);

      if (mode !== 'mod') {
        div = res.div.neg();
      }

      return {
        div: div,
        mod: res.mod
      };
    }

    if ((this.negative & num.negative) !== 0) {
      res = this.neg().divmod(num.neg(), mode);

      if (mode !== 'div') {
        mod = res.mod.neg();
        if (positive && mod.negative !== 0) {
          mod.isub(num);
        }
      }

      return {
        div: res.div,
        mod: mod
      };
    }

    // Both numbers are positive at this point

    // Strip both numbers to approximate shift value
    if (num.length > this.length || this.cmp(num) < 0) {
      return {
        div: new BN(0),
        mod: this
      };
    }

    // Very short reduction
    if (num.length === 1) {
      if (mode === 'div') {
        return {
          div: this.divn(num.words[0]),
          mod: null
        };
      }

      if (mode === 'mod') {
        return {
          div: null,
          mod: new BN(this.modrn(num.words[0]))
        };
      }

      return {
        div: this.divn(num.words[0]),
        mod: new BN(this.modrn(num.words[0]))
      };
    }

    return this._wordDiv(num, mode);
  };

  // Find `this` / `num`
  BN.prototype.div = function div (num) {
    return this.divmod(num, 'div', false).div;
  };

  // Find `this` % `num`
  BN.prototype.mod = function mod (num) {
    return this.divmod(num, 'mod', false).mod;
  };

  BN.prototype.umod = function umod (num) {
    return this.divmod(num, 'mod', true).mod;
  };

  // Find Round(`this` / `num`)
  BN.prototype.divRound = function divRound (num) {
    var dm = this.divmod(num);

    // Fast case - exact division
    if (dm.mod.isZero()) return dm.div;

    var mod = dm.div.negative !== 0 ? dm.mod.isub(num) : dm.mod;

    var half = num.ushrn(1);
    var r2 = num.andln(1);
    var cmp = mod.cmp(half);

    // Round down
    if (cmp < 0 || (r2 === 1 && cmp === 0)) return dm.div;

    // Round up
    return dm.div.negative !== 0 ? dm.div.isubn(1) : dm.div.iaddn(1);
  };

  BN.prototype.modrn = function modrn (num) {
    var isNegNum = num < 0;
    if (isNegNum) num = -num;

    assert(num <= 0x3ffffff);
    var p = (1 << 26) % num;

    var acc = 0;
    for (var i = this.length - 1; i >= 0; i--) {
      acc = (p * acc + (this.words[i] | 0)) % num;
    }

    return isNegNum ? -acc : acc;
  };

  // WARNING: DEPRECATED
  BN.prototype.modn = function modn (num) {
    return this.modrn(num);
  };

  // In-place division by number
  BN.prototype.idivn = function idivn (num) {
    var isNegNum = num < 0;
    if (isNegNum) num = -num;

    assert(num <= 0x3ffffff);

    var carry = 0;
    for (var i = this.length - 1; i >= 0; i--) {
      var w = (this.words[i] | 0) + carry * 0x4000000;
      this.words[i] = (w / num) | 0;
      carry = w % num;
    }

    this._strip();
    return isNegNum ? this.ineg() : this;
  };

  BN.prototype.divn = function divn (num) {
    return this.clone().idivn(num);
  };

  BN.prototype.egcd = function egcd (p) {
    assert(p.negative === 0);
    assert(!p.isZero());

    var x = this;
    var y = p.clone();

    if (x.negative !== 0) {
      x = x.umod(p);
    } else {
      x = x.clone();
    }

    // A * x + B * y = x
    var A = new BN(1);
    var B = new BN(0);

    // C * x + D * y = y
    var C = new BN(0);
    var D = new BN(1);

    var g = 0;

    while (x.isEven() && y.isEven()) {
      x.iushrn(1);
      y.iushrn(1);
      ++g;
    }

    var yp = y.clone();
    var xp = x.clone();

    while (!x.isZero()) {
      for (var i = 0, im = 1; (x.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
      if (i > 0) {
        x.iushrn(i);
        while (i-- > 0) {
          if (A.isOdd() || B.isOdd()) {
            A.iadd(yp);
            B.isub(xp);
          }

          A.iushrn(1);
          B.iushrn(1);
        }
      }

      for (var j = 0, jm = 1; (y.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
      if (j > 0) {
        y.iushrn(j);
        while (j-- > 0) {
          if (C.isOdd() || D.isOdd()) {
            C.iadd(yp);
            D.isub(xp);
          }

          C.iushrn(1);
          D.iushrn(1);
        }
      }

      if (x.cmp(y) >= 0) {
        x.isub(y);
        A.isub(C);
        B.isub(D);
      } else {
        y.isub(x);
        C.isub(A);
        D.isub(B);
      }
    }

    return {
      a: C,
      b: D,
      gcd: y.iushln(g)
    };
  };

  // This is reduced incarnation of the binary EEA
  // above, designated to invert members of the
  // _prime_ fields F(p) at a maximal speed
  BN.prototype._invmp = function _invmp (p) {
    assert(p.negative === 0);
    assert(!p.isZero());

    var a = this;
    var b = p.clone();

    if (a.negative !== 0) {
      a = a.umod(p);
    } else {
      a = a.clone();
    }

    var x1 = new BN(1);
    var x2 = new BN(0);

    var delta = b.clone();

    while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
      for (var i = 0, im = 1; (a.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
      if (i > 0) {
        a.iushrn(i);
        while (i-- > 0) {
          if (x1.isOdd()) {
            x1.iadd(delta);
          }

          x1.iushrn(1);
        }
      }

      for (var j = 0, jm = 1; (b.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
      if (j > 0) {
        b.iushrn(j);
        while (j-- > 0) {
          if (x2.isOdd()) {
            x2.iadd(delta);
          }

          x2.iushrn(1);
        }
      }

      if (a.cmp(b) >= 0) {
        a.isub(b);
        x1.isub(x2);
      } else {
        b.isub(a);
        x2.isub(x1);
      }
    }

    var res;
    if (a.cmpn(1) === 0) {
      res = x1;
    } else {
      res = x2;
    }

    if (res.cmpn(0) < 0) {
      res.iadd(p);
    }

    return res;
  };

  BN.prototype.gcd = function gcd (num) {
    if (this.isZero()) return num.abs();
    if (num.isZero()) return this.abs();

    var a = this.clone();
    var b = num.clone();
    a.negative = 0;
    b.negative = 0;

    // Remove common factor of two
    for (var shift = 0; a.isEven() && b.isEven(); shift++) {
      a.iushrn(1);
      b.iushrn(1);
    }

    do {
      while (a.isEven()) {
        a.iushrn(1);
      }
      while (b.isEven()) {
        b.iushrn(1);
      }

      var r = a.cmp(b);
      if (r < 0) {
        // Swap `a` and `b` to make `a` always bigger than `b`
        var t = a;
        a = b;
        b = t;
      } else if (r === 0 || b.cmpn(1) === 0) {
        break;
      }

      a.isub(b);
    } while (true);

    return b.iushln(shift);
  };

  // Invert number in the field F(num)
  BN.prototype.invm = function invm (num) {
    return this.egcd(num).a.umod(num);
  };

  BN.prototype.isEven = function isEven () {
    return (this.words[0] & 1) === 0;
  };

  BN.prototype.isOdd = function isOdd () {
    return (this.words[0] & 1) === 1;
  };

  // And first word and num
  BN.prototype.andln = function andln (num) {
    return this.words[0] & num;
  };

  // Increment at the bit position in-line
  BN.prototype.bincn = function bincn (bit) {
    assert(typeof bit === 'number');
    var r = bit % 26;
    var s = (bit - r) / 26;
    var q = 1 << r;

    // Fast case: bit is much higher than all existing words
    if (this.length <= s) {
      this._expand(s + 1);
      this.words[s] |= q;
      return this;
    }

    // Add bit and propagate, if needed
    var carry = q;
    for (var i = s; carry !== 0 && i < this.length; i++) {
      var w = this.words[i] | 0;
      w += carry;
      carry = w >>> 26;
      w &= 0x3ffffff;
      this.words[i] = w;
    }
    if (carry !== 0) {
      this.words[i] = carry;
      this.length++;
    }
    return this;
  };

  BN.prototype.isZero = function isZero () {
    return this.length === 1 && this.words[0] === 0;
  };

  BN.prototype.cmpn = function cmpn (num) {
    var negative = num < 0;

    if (this.negative !== 0 && !negative) return -1;
    if (this.negative === 0 && negative) return 1;

    this._strip();

    var res;
    if (this.length > 1) {
      res = 1;
    } else {
      if (negative) {
        num = -num;
      }

      assert(num <= 0x3ffffff, 'Number is too big');

      var w = this.words[0] | 0;
      res = w === num ? 0 : w < num ? -1 : 1;
    }
    if (this.negative !== 0) return -res | 0;
    return res;
  };

  // Compare two numbers and return:
  // 1 - if `this` > `num`
  // 0 - if `this` == `num`
  // -1 - if `this` < `num`
  BN.prototype.cmp = function cmp (num) {
    if (this.negative !== 0 && num.negative === 0) return -1;
    if (this.negative === 0 && num.negative !== 0) return 1;

    var res = this.ucmp(num);
    if (this.negative !== 0) return -res | 0;
    return res;
  };

  // Unsigned comparison
  BN.prototype.ucmp = function ucmp (num) {
    // At this point both numbers have the same sign
    if (this.length > num.length) return 1;
    if (this.length < num.length) return -1;

    var res = 0;
    for (var i = this.length - 1; i >= 0; i--) {
      var a = this.words[i] | 0;
      var b = num.words[i] | 0;

      if (a === b) continue;
      if (a < b) {
        res = -1;
      } else if (a > b) {
        res = 1;
      }
      break;
    }
    return res;
  };

  BN.prototype.gtn = function gtn (num) {
    return this.cmpn(num) === 1;
  };

  BN.prototype.gt = function gt (num) {
    return this.cmp(num) === 1;
  };

  BN.prototype.gten = function gten (num) {
    return this.cmpn(num) >= 0;
  };

  BN.prototype.gte = function gte (num) {
    return this.cmp(num) >= 0;
  };

  BN.prototype.ltn = function ltn (num) {
    return this.cmpn(num) === -1;
  };

  BN.prototype.lt = function lt (num) {
    return this.cmp(num) === -1;
  };

  BN.prototype.lten = function lten (num) {
    return this.cmpn(num) <= 0;
  };

  BN.prototype.lte = function lte (num) {
    return this.cmp(num) <= 0;
  };

  BN.prototype.eqn = function eqn (num) {
    return this.cmpn(num) === 0;
  };

  BN.prototype.eq = function eq (num) {
    return this.cmp(num) === 0;
  };

  //
  // A reduce context, could be using montgomery or something better, depending
  // on the `m` itself.
  //
  BN.red = function red (num) {
    return new Red(num);
  };

  BN.prototype.toRed = function toRed (ctx) {
    assert(!this.red, 'Already a number in reduction context');
    assert(this.negative === 0, 'red works only with positives');
    return ctx.convertTo(this)._forceRed(ctx);
  };

  BN.prototype.fromRed = function fromRed () {
    assert(this.red, 'fromRed works only with numbers in reduction context');
    return this.red.convertFrom(this);
  };

  BN.prototype._forceRed = function _forceRed (ctx) {
    this.red = ctx;
    return this;
  };

  BN.prototype.forceRed = function forceRed (ctx) {
    assert(!this.red, 'Already a number in reduction context');
    return this._forceRed(ctx);
  };

  BN.prototype.redAdd = function redAdd (num) {
    assert(this.red, 'redAdd works only with red numbers');
    return this.red.add(this, num);
  };

  BN.prototype.redIAdd = function redIAdd (num) {
    assert(this.red, 'redIAdd works only with red numbers');
    return this.red.iadd(this, num);
  };

  BN.prototype.redSub = function redSub (num) {
    assert(this.red, 'redSub works only with red numbers');
    return this.red.sub(this, num);
  };

  BN.prototype.redISub = function redISub (num) {
    assert(this.red, 'redISub works only with red numbers');
    return this.red.isub(this, num);
  };

  BN.prototype.redShl = function redShl (num) {
    assert(this.red, 'redShl works only with red numbers');
    return this.red.shl(this, num);
  };

  BN.prototype.redMul = function redMul (num) {
    assert(this.red, 'redMul works only with red numbers');
    this.red._verify2(this, num);
    return this.red.mul(this, num);
  };

  BN.prototype.redIMul = function redIMul (num) {
    assert(this.red, 'redMul works only with red numbers');
    this.red._verify2(this, num);
    return this.red.imul(this, num);
  };

  BN.prototype.redSqr = function redSqr () {
    assert(this.red, 'redSqr works only with red numbers');
    this.red._verify1(this);
    return this.red.sqr(this);
  };

  BN.prototype.redISqr = function redISqr () {
    assert(this.red, 'redISqr works only with red numbers');
    this.red._verify1(this);
    return this.red.isqr(this);
  };

  // Square root over p
  BN.prototype.redSqrt = function redSqrt () {
    assert(this.red, 'redSqrt works only with red numbers');
    this.red._verify1(this);
    return this.red.sqrt(this);
  };

  BN.prototype.redInvm = function redInvm () {
    assert(this.red, 'redInvm works only with red numbers');
    this.red._verify1(this);
    return this.red.invm(this);
  };

  // Return negative clone of `this` % `red modulo`
  BN.prototype.redNeg = function redNeg () {
    assert(this.red, 'redNeg works only with red numbers');
    this.red._verify1(this);
    return this.red.neg(this);
  };

  BN.prototype.redPow = function redPow (num) {
    assert(this.red && !num.red, 'redPow(normalNum)');
    this.red._verify1(this);
    return this.red.pow(this, num);
  };

  // Prime numbers with efficient reduction
  var primes = {
    k256: null,
    p224: null,
    p192: null,
    p25519: null
  };

  // Pseudo-Mersenne prime
  function MPrime (name, p) {
    // P = 2 ^ N - K
    this.name = name;
    this.p = new BN(p, 16);
    this.n = this.p.bitLength();
    this.k = new BN(1).iushln(this.n).isub(this.p);

    this.tmp = this._tmp();
  }

  MPrime.prototype._tmp = function _tmp () {
    var tmp = new BN(null);
    tmp.words = new Array(Math.ceil(this.n / 13));
    return tmp;
  };

  MPrime.prototype.ireduce = function ireduce (num) {
    // Assumes that `num` is less than `P^2`
    // num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
    var r = num;
    var rlen;

    do {
      this.split(r, this.tmp);
      r = this.imulK(r);
      r = r.iadd(this.tmp);
      rlen = r.bitLength();
    } while (rlen > this.n);

    var cmp = rlen < this.n ? -1 : r.ucmp(this.p);
    if (cmp === 0) {
      r.words[0] = 0;
      r.length = 1;
    } else if (cmp > 0) {
      r.isub(this.p);
    } else {
      if (r.strip !== undefined) {
        // r is a BN v4 instance
        r.strip();
      } else {
        // r is a BN v5 instance
        r._strip();
      }
    }

    return r;
  };

  MPrime.prototype.split = function split (input, out) {
    input.iushrn(this.n, 0, out);
  };

  MPrime.prototype.imulK = function imulK (num) {
    return num.imul(this.k);
  };

  function K256 () {
    MPrime.call(
      this,
      'k256',
      'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f');
  }
  inherits(K256, MPrime);

  K256.prototype.split = function split (input, output) {
    // 256 = 9 * 26 + 22
    var mask = 0x3fffff;

    var outLen = Math.min(input.length, 9);
    for (var i = 0; i < outLen; i++) {
      output.words[i] = input.words[i];
    }
    output.length = outLen;

    if (input.length <= 9) {
      input.words[0] = 0;
      input.length = 1;
      return;
    }

    // Shift by 9 limbs
    var prev = input.words[9];
    output.words[output.length++] = prev & mask;

    for (i = 10; i < input.length; i++) {
      var next = input.words[i] | 0;
      input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);
      prev = next;
    }
    prev >>>= 22;
    input.words[i - 10] = prev;
    if (prev === 0 && input.length > 10) {
      input.length -= 10;
    } else {
      input.length -= 9;
    }
  };

  K256.prototype.imulK = function imulK (num) {
    // K = 0x1000003d1 = [ 0x40, 0x3d1 ]
    num.words[num.length] = 0;
    num.words[num.length + 1] = 0;
    num.length += 2;

    // bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
    var lo = 0;
    for (var i = 0; i < num.length; i++) {
      var w = num.words[i] | 0;
      lo += w * 0x3d1;
      num.words[i] = lo & 0x3ffffff;
      lo = w * 0x40 + ((lo / 0x4000000) | 0);
    }

    // Fast length reduction
    if (num.words[num.length - 1] === 0) {
      num.length--;
      if (num.words[num.length - 1] === 0) {
        num.length--;
      }
    }
    return num;
  };

  function P224 () {
    MPrime.call(
      this,
      'p224',
      'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001');
  }
  inherits(P224, MPrime);

  function P192 () {
    MPrime.call(
      this,
      'p192',
      'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff');
  }
  inherits(P192, MPrime);

  function P25519 () {
    // 2 ^ 255 - 19
    MPrime.call(
      this,
      '25519',
      '7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed');
  }
  inherits(P25519, MPrime);

  P25519.prototype.imulK = function imulK (num) {
    // K = 0x13
    var carry = 0;
    for (var i = 0; i < num.length; i++) {
      var hi = (num.words[i] | 0) * 0x13 + carry;
      var lo = hi & 0x3ffffff;
      hi >>>= 26;

      num.words[i] = lo;
      carry = hi;
    }
    if (carry !== 0) {
      num.words[num.length++] = carry;
    }
    return num;
  };

  // Exported mostly for testing purposes, use plain name instead
  BN._prime = function prime (name) {
    // Cached version of prime
    if (primes[name]) return primes[name];

    var prime;
    if (name === 'k256') {
      prime = new K256();
    } else if (name === 'p224') {
      prime = new P224();
    } else if (name === 'p192') {
      prime = new P192();
    } else if (name === 'p25519') {
      prime = new P25519();
    } else {
      throw new Error('Unknown prime ' + name);
    }
    primes[name] = prime;

    return prime;
  };

  //
  // Base reduction engine
  //
  function Red (m) {
    if (typeof m === 'string') {
      var prime = BN._prime(m);
      this.m = prime.p;
      this.prime = prime;
    } else {
      assert(m.gtn(1), 'modulus must be greater than 1');
      this.m = m;
      this.prime = null;
    }
  }

  Red.prototype._verify1 = function _verify1 (a) {
    assert(a.negative === 0, 'red works only with positives');
    assert(a.red, 'red works only with red numbers');
  };

  Red.prototype._verify2 = function _verify2 (a, b) {
    assert((a.negative | b.negative) === 0, 'red works only with positives');
    assert(a.red && a.red === b.red,
      'red works only with red numbers');
  };

  Red.prototype.imod = function imod (a) {
    if (this.prime) return this.prime.ireduce(a)._forceRed(this);

    move(a, a.umod(this.m)._forceRed(this));
    return a;
  };

  Red.prototype.neg = function neg (a) {
    if (a.isZero()) {
      return a.clone();
    }

    return this.m.sub(a)._forceRed(this);
  };

  Red.prototype.add = function add (a, b) {
    this._verify2(a, b);

    var res = a.add(b);
    if (res.cmp(this.m) >= 0) {
      res.isub(this.m);
    }
    return res._forceRed(this);
  };

  Red.prototype.iadd = function iadd (a, b) {
    this._verify2(a, b);

    var res = a.iadd(b);
    if (res.cmp(this.m) >= 0) {
      res.isub(this.m);
    }
    return res;
  };

  Red.prototype.sub = function sub (a, b) {
    this._verify2(a, b);

    var res = a.sub(b);
    if (res.cmpn(0) < 0) {
      res.iadd(this.m);
    }
    return res._forceRed(this);
  };

  Red.prototype.isub = function isub (a, b) {
    this._verify2(a, b);

    var res = a.isub(b);
    if (res.cmpn(0) < 0) {
      res.iadd(this.m);
    }
    return res;
  };

  Red.prototype.shl = function shl (a, num) {
    this._verify1(a);
    return this.imod(a.ushln(num));
  };

  Red.prototype.imul = function imul (a, b) {
    this._verify2(a, b);
    return this.imod(a.imul(b));
  };

  Red.prototype.mul = function mul (a, b) {
    this._verify2(a, b);
    return this.imod(a.mul(b));
  };

  Red.prototype.isqr = function isqr (a) {
    return this.imul(a, a.clone());
  };

  Red.prototype.sqr = function sqr (a) {
    return this.mul(a, a);
  };

  Red.prototype.sqrt = function sqrt (a) {
    if (a.isZero()) return a.clone();

    var mod3 = this.m.andln(3);
    assert(mod3 % 2 === 1);

    // Fast case
    if (mod3 === 3) {
      var pow = this.m.add(new BN(1)).iushrn(2);
      return this.pow(a, pow);
    }

    // Tonelli-Shanks algorithm (Totally unoptimized and slow)
    //
    // Find Q and S, that Q * 2 ^ S = (P - 1)
    var q = this.m.subn(1);
    var s = 0;
    while (!q.isZero() && q.andln(1) === 0) {
      s++;
      q.iushrn(1);
    }
    assert(!q.isZero());

    var one = new BN(1).toRed(this);
    var nOne = one.redNeg();

    // Find quadratic non-residue
    // NOTE: Max is such because of generalized Riemann hypothesis.
    var lpow = this.m.subn(1).iushrn(1);
    var z = this.m.bitLength();
    z = new BN(2 * z * z).toRed(this);

    while (this.pow(z, lpow).cmp(nOne) !== 0) {
      z.redIAdd(nOne);
    }

    var c = this.pow(z, q);
    var r = this.pow(a, q.addn(1).iushrn(1));
    var t = this.pow(a, q);
    var m = s;
    while (t.cmp(one) !== 0) {
      var tmp = t;
      for (var i = 0; tmp.cmp(one) !== 0; i++) {
        tmp = tmp.redSqr();
      }
      assert(i < m);
      var b = this.pow(c, new BN(1).iushln(m - i - 1));

      r = r.redMul(b);
      c = b.redSqr();
      t = t.redMul(c);
      m = i;
    }

    return r;
  };

  Red.prototype.invm = function invm (a) {
    var inv = a._invmp(this.m);
    if (inv.negative !== 0) {
      inv.negative = 0;
      return this.imod(inv).redNeg();
    } else {
      return this.imod(inv);
    }
  };

  Red.prototype.pow = function pow (a, num) {
    if (num.isZero()) return new BN(1).toRed(this);
    if (num.cmpn(1) === 0) return a.clone();

    var windowSize = 4;
    var wnd = new Array(1 << windowSize);
    wnd[0] = new BN(1).toRed(this);
    wnd[1] = a;
    for (var i = 2; i < wnd.length; i++) {
      wnd[i] = this.mul(wnd[i - 1], a);
    }

    var res = wnd[0];
    var current = 0;
    var currentLen = 0;
    var start = num.bitLength() % 26;
    if (start === 0) {
      start = 26;
    }

    for (i = num.length - 1; i >= 0; i--) {
      var word = num.words[i];
      for (var j = start - 1; j >= 0; j--) {
        var bit = (word >> j) & 1;
        if (res !== wnd[0]) {
          res = this.sqr(res);
        }

        if (bit === 0 && current === 0) {
          currentLen = 0;
          continue;
        }

        current <<= 1;
        current |= bit;
        currentLen++;
        if (currentLen !== windowSize && (i !== 0 || j !== 0)) continue;

        res = this.mul(res, wnd[current]);
        currentLen = 0;
        current = 0;
      }
      start = 26;
    }

    return res;
  };

  Red.prototype.convertTo = function convertTo (num) {
    var r = num.umod(this.m);

    return r === num ? r.clone() : r;
  };

  Red.prototype.convertFrom = function convertFrom (num) {
    var res = num.clone();
    res.red = null;
    return res;
  };

  //
  // Montgomery method engine
  //

  BN.mont = function mont (num) {
    return new Mont(num);
  };

  function Mont (m) {
    Red.call(this, m);

    this.shift = this.m.bitLength();
    if (this.shift % 26 !== 0) {
      this.shift += 26 - (this.shift % 26);
    }

    this.r = new BN(1).iushln(this.shift);
    this.r2 = this.imod(this.r.sqr());
    this.rinv = this.r._invmp(this.m);

    this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
    this.minv = this.minv.umod(this.r);
    this.minv = this.r.sub(this.minv);
  }
  inherits(Mont, Red);

  Mont.prototype.convertTo = function convertTo (num) {
    return this.imod(num.ushln(this.shift));
  };

  Mont.prototype.convertFrom = function convertFrom (num) {
    var r = this.imod(num.mul(this.rinv));
    r.red = null;
    return r;
  };

  Mont.prototype.imul = function imul (a, b) {
    if (a.isZero() || b.isZero()) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    var t = a.imul(b);
    var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    var u = t.isub(c).iushrn(this.shift);
    var res = u;

    if (u.cmp(this.m) >= 0) {
      res = u.isub(this.m);
    } else if (u.cmpn(0) < 0) {
      res = u.iadd(this.m);
    }

    return res._forceRed(this);
  };

  Mont.prototype.mul = function mul (a, b) {
    if (a.isZero() || b.isZero()) return new BN(0)._forceRed(this);

    var t = a.mul(b);
    var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
    var u = t.isub(c).iushrn(this.shift);
    var res = u;
    if (u.cmp(this.m) >= 0) {
      res = u.isub(this.m);
    } else if (u.cmpn(0) < 0) {
      res = u.iadd(this.m);
    }

    return res._forceRed(this);
  };

  Mont.prototype.invm = function invm (a) {
    // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
    var res = this.imod(a._invmp(this.m).mul(this.r2));
    return res._forceRed(this);
  };
})(typeof module === 'undefined' || module, this);

},{"buffer":60}],60:[function(require,module,exports){

},{}],61:[function(require,module,exports){
var basex = require('base-x')
var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

module.exports = basex(ALPHABET)

},{"base-x":48}],62:[function(require,module,exports){
(function (Buffer){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this,require("buffer").Buffer)
},{"base64-js":49,"buffer":62,"ieee754":64}],63:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var objectCreate = Object.create || objectCreatePolyfill
var objectKeys = Object.keys || objectKeysPolyfill
var bind = Function.prototype.bind || functionBindPolyfill

function EventEmitter() {
  if (!this._events || !Object.prototype.hasOwnProperty.call(this, '_events')) {
    this._events = objectCreate(null);
    this._eventsCount = 0;
  }

  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
var defaultMaxListeners = 10;

var hasDefineProperty;
try {
  var o = {};
  if (Object.defineProperty) Object.defineProperty(o, 'x', { value: 0 });
  hasDefineProperty = o.x === 0;
} catch (err) { hasDefineProperty = false }
if (hasDefineProperty) {
  Object.defineProperty(EventEmitter, 'defaultMaxListeners', {
    enumerable: true,
    get: function() {
      return defaultMaxListeners;
    },
    set: function(arg) {
      // check whether the input is a positive number (whose value is zero or
      // greater and not a NaN).
      if (typeof arg !== 'number' || arg < 0 || arg !== arg)
        throw new TypeError('"defaultMaxListeners" must be a positive number');
      defaultMaxListeners = arg;
    }
  });
} else {
  EventEmitter.defaultMaxListeners = defaultMaxListeners;
}

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function setMaxListeners(n) {
  if (typeof n !== 'number' || n < 0 || isNaN(n))
    throw new TypeError('"n" argument must be a positive number');
  this._maxListeners = n;
  return this;
};

function $getMaxListeners(that) {
  if (that._maxListeners === undefined)
    return EventEmitter.defaultMaxListeners;
  return that._maxListeners;
}

EventEmitter.prototype.getMaxListeners = function getMaxListeners() {
  return $getMaxListeners(this);
};

// These standalone emit* functions are used to optimize calling of event
// handlers for fast cases because emit() itself often has a variable number of
// arguments and can be deoptimized because of that. These functions always have
// the same number of arguments and thus do not get deoptimized, so the code
// inside them can execute faster.
function emitNone(handler, isFn, self) {
  if (isFn)
    handler.call(self);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self);
  }
}
function emitOne(handler, isFn, self, arg1) {
  if (isFn)
    handler.call(self, arg1);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self, arg1);
  }
}
function emitTwo(handler, isFn, self, arg1, arg2) {
  if (isFn)
    handler.call(self, arg1, arg2);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self, arg1, arg2);
  }
}
function emitThree(handler, isFn, self, arg1, arg2, arg3) {
  if (isFn)
    handler.call(self, arg1, arg2, arg3);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].call(self, arg1, arg2, arg3);
  }
}

function emitMany(handler, isFn, self, args) {
  if (isFn)
    handler.apply(self, args);
  else {
    var len = handler.length;
    var listeners = arrayClone(handler, len);
    for (var i = 0; i < len; ++i)
      listeners[i].apply(self, args);
  }
}

EventEmitter.prototype.emit = function emit(type) {
  var er, handler, len, args, i, events;
  var doError = (type === 'error');

  events = this._events;
  if (events)
    doError = (doError && events.error == null);
  else if (!doError)
    return false;

  // If there is no 'error' event listener then throw.
  if (doError) {
    if (arguments.length > 1)
      er = arguments[1];
    if (er instanceof Error) {
      throw er; // Unhandled 'error' event
    } else {
      // At least give some kind of context to the user
      var err = new Error('Unhandled "error" event. (' + er + ')');
      err.context = er;
      throw err;
    }
    return false;
  }

  handler = events[type];

  if (!handler)
    return false;

  var isFn = typeof handler === 'function';
  len = arguments.length;
  switch (len) {
      // fast cases
    case 1:
      emitNone(handler, isFn, this);
      break;
    case 2:
      emitOne(handler, isFn, this, arguments[1]);
      break;
    case 3:
      emitTwo(handler, isFn, this, arguments[1], arguments[2]);
      break;
    case 4:
      emitThree(handler, isFn, this, arguments[1], arguments[2], arguments[3]);
      break;
      // slower
    default:
      args = new Array(len - 1);
      for (i = 1; i < len; i++)
        args[i - 1] = arguments[i];
      emitMany(handler, isFn, this, args);
  }

  return true;
};

function _addListener(target, type, listener, prepend) {
  var m;
  var events;
  var existing;

  if (typeof listener !== 'function')
    throw new TypeError('"listener" argument must be a function');

  events = target._events;
  if (!events) {
    events = target._events = objectCreate(null);
    target._eventsCount = 0;
  } else {
    // To avoid recursion in the case that type === "newListener"! Before
    // adding it to the listeners, first emit "newListener".
    if (events.newListener) {
      target.emit('newListener', type,
          listener.listener ? listener.listener : listener);

      // Re-assign `events` because a newListener handler could have caused the
      // this._events to be assigned to a new object
      events = target._events;
    }
    existing = events[type];
  }

  if (!existing) {
    // Optimize the case of one listener. Don't need the extra array object.
    existing = events[type] = listener;
    ++target._eventsCount;
  } else {
    if (typeof existing === 'function') {
      // Adding the second element, need to change to array.
      existing = events[type] =
          prepend ? [listener, existing] : [existing, listener];
    } else {
      // If we've already got an array, just append.
      if (prepend) {
        existing.unshift(listener);
      } else {
        existing.push(listener);
      }
    }

    // Check for listener leak
    if (!existing.warned) {
      m = $getMaxListeners(target);
      if (m && m > 0 && existing.length > m) {
        existing.warned = true;
        var w = new Error('Possible EventEmitter memory leak detected. ' +
            existing.length + ' "' + String(type) + '" listeners ' +
            'added. Use emitter.setMaxListeners() to ' +
            'increase limit.');
        w.name = 'MaxListenersExceededWarning';
        w.emitter = target;
        w.type = type;
        w.count = existing.length;
        if (typeof console === 'object' && console.warn) {
          console.warn('%s: %s', w.name, w.message);
        }
      }
    }
  }

  return target;
}

EventEmitter.prototype.addListener = function addListener(type, listener) {
  return _addListener(this, type, listener, false);
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.prependListener =
    function prependListener(type, listener) {
      return _addListener(this, type, listener, true);
    };

function onceWrapper() {
  if (!this.fired) {
    this.target.removeListener(this.type, this.wrapFn);
    this.fired = true;
    switch (arguments.length) {
      case 0:
        return this.listener.call(this.target);
      case 1:
        return this.listener.call(this.target, arguments[0]);
      case 2:
        return this.listener.call(this.target, arguments[0], arguments[1]);
      case 3:
        return this.listener.call(this.target, arguments[0], arguments[1],
            arguments[2]);
      default:
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; ++i)
          args[i] = arguments[i];
        this.listener.apply(this.target, args);
    }
  }
}

function _onceWrap(target, type, listener) {
  var state = { fired: false, wrapFn: undefined, target: target, type: type, listener: listener };
  var wrapped = bind.call(onceWrapper, state);
  wrapped.listener = listener;
  state.wrapFn = wrapped;
  return wrapped;
}

EventEmitter.prototype.once = function once(type, listener) {
  if (typeof listener !== 'function')
    throw new TypeError('"listener" argument must be a function');
  this.on(type, _onceWrap(this, type, listener));
  return this;
};

EventEmitter.prototype.prependOnceListener =
    function prependOnceListener(type, listener) {
      if (typeof listener !== 'function')
        throw new TypeError('"listener" argument must be a function');
      this.prependListener(type, _onceWrap(this, type, listener));
      return this;
    };

// Emits a 'removeListener' event if and only if the listener was removed.
EventEmitter.prototype.removeListener =
    function removeListener(type, listener) {
      var list, events, position, i, originalListener;

      if (typeof listener !== 'function')
        throw new TypeError('"listener" argument must be a function');

      events = this._events;
      if (!events)
        return this;

      list = events[type];
      if (!list)
        return this;

      if (list === listener || list.listener === listener) {
        if (--this._eventsCount === 0)
          this._events = objectCreate(null);
        else {
          delete events[type];
          if (events.removeListener)
            this.emit('removeListener', type, list.listener || listener);
        }
      } else if (typeof list !== 'function') {
        position = -1;

        for (i = list.length - 1; i >= 0; i--) {
          if (list[i] === listener || list[i].listener === listener) {
            originalListener = list[i].listener;
            position = i;
            break;
          }
        }

        if (position < 0)
          return this;

        if (position === 0)
          list.shift();
        else
          spliceOne(list, position);

        if (list.length === 1)
          events[type] = list[0];

        if (events.removeListener)
          this.emit('removeListener', type, originalListener || listener);
      }

      return this;
    };

EventEmitter.prototype.removeAllListeners =
    function removeAllListeners(type) {
      var listeners, events, i;

      events = this._events;
      if (!events)
        return this;

      // not listening for removeListener, no need to emit
      if (!events.removeListener) {
        if (arguments.length === 0) {
          this._events = objectCreate(null);
          this._eventsCount = 0;
        } else if (events[type]) {
          if (--this._eventsCount === 0)
            this._events = objectCreate(null);
          else
            delete events[type];
        }
        return this;
      }

      // emit removeListener for all listeners on all events
      if (arguments.length === 0) {
        var keys = objectKeys(events);
        var key;
        for (i = 0; i < keys.length; ++i) {
          key = keys[i];
          if (key === 'removeListener') continue;
          this.removeAllListeners(key);
        }
        this.removeAllListeners('removeListener');
        this._events = objectCreate(null);
        this._eventsCount = 0;
        return this;
      }

      listeners = events[type];

      if (typeof listeners === 'function') {
        this.removeListener(type, listeners);
      } else if (listeners) {
        // LIFO order
        for (i = listeners.length - 1; i >= 0; i--) {
          this.removeListener(type, listeners[i]);
        }
      }

      return this;
    };

function _listeners(target, type, unwrap) {
  var events = target._events;

  if (!events)
    return [];

  var evlistener = events[type];
  if (!evlistener)
    return [];

  if (typeof evlistener === 'function')
    return unwrap ? [evlistener.listener || evlistener] : [evlistener];

  return unwrap ? unwrapListeners(evlistener) : arrayClone(evlistener, evlistener.length);
}

EventEmitter.prototype.listeners = function listeners(type) {
  return _listeners(this, type, true);
};

EventEmitter.prototype.rawListeners = function rawListeners(type) {
  return _listeners(this, type, false);
};

EventEmitter.listenerCount = function(emitter, type) {
  if (typeof emitter.listenerCount === 'function') {
    return emitter.listenerCount(type);
  } else {
    return listenerCount.call(emitter, type);
  }
};

EventEmitter.prototype.listenerCount = listenerCount;
function listenerCount(type) {
  var events = this._events;

  if (events) {
    var evlistener = events[type];

    if (typeof evlistener === 'function') {
      return 1;
    } else if (evlistener) {
      return evlistener.length;
    }
  }

  return 0;
}

EventEmitter.prototype.eventNames = function eventNames() {
  return this._eventsCount > 0 ? Reflect.ownKeys(this._events) : [];
};

// About 1.5x faster than the two-arg version of Array#splice().
function spliceOne(list, index) {
  for (var i = index, k = i + 1, n = list.length; k < n; i += 1, k += 1)
    list[i] = list[k];
  list.pop();
}

function arrayClone(arr, n) {
  var copy = new Array(n);
  for (var i = 0; i < n; ++i)
    copy[i] = arr[i];
  return copy;
}

function unwrapListeners(arr) {
  var ret = new Array(arr.length);
  for (var i = 0; i < ret.length; ++i) {
    ret[i] = arr[i].listener || arr[i];
  }
  return ret;
}

function objectCreatePolyfill(proto) {
  var F = function() {};
  F.prototype = proto;
  return new F;
}
function objectKeysPolyfill(obj) {
  var keys = [];
  for (var k in obj) if (Object.prototype.hasOwnProperty.call(obj, k)) {
    keys.push(k);
  }
  return k;
}
function functionBindPolyfill(context) {
  var fn = this;
  return function () {
    return fn.apply(context, arguments);
  };
}

},{}],64:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],65:[function(require,module,exports){
if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      ctor.prototype = Object.create(superCtor.prototype, {
        constructor: {
          value: ctor,
          enumerable: false,
          writable: true,
          configurable: true
        }
      })
    }
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    if (superCtor) {
      ctor.super_ = superCtor
      var TempCtor = function () {}
      TempCtor.prototype = superCtor.prototype
      ctor.prototype = new TempCtor()
      ctor.prototype.constructor = ctor
    }
  }
}

},{}],66:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],67:[function(require,module,exports){
'use strict';

function _inheritsLoose(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype); subClass.prototype.constructor = subClass; subClass.__proto__ = superClass; }

var codes = {};

function createErrorType(code, message, Base) {
  if (!Base) {
    Base = Error;
  }

  function getMessage(arg1, arg2, arg3) {
    if (typeof message === 'string') {
      return message;
    } else {
      return message(arg1, arg2, arg3);
    }
  }

  var NodeError =
  /*#__PURE__*/
  function (_Base) {
    _inheritsLoose(NodeError, _Base);

    function NodeError(arg1, arg2, arg3) {
      return _Base.call(this, getMessage(arg1, arg2, arg3)) || this;
    }

    return NodeError;
  }(Base);

  NodeError.prototype.name = Base.name;
  NodeError.prototype.code = code;
  codes[code] = NodeError;
} // https://github.com/nodejs/node/blob/v10.8.0/lib/internal/errors.js


function oneOf(expected, thing) {
  if (Array.isArray(expected)) {
    var len = expected.length;
    expected = expected.map(function (i) {
      return String(i);
    });

    if (len > 2) {
      return "one of ".concat(thing, " ").concat(expected.slice(0, len - 1).join(', '), ", or ") + expected[len - 1];
    } else if (len === 2) {
      return "one of ".concat(thing, " ").concat(expected[0], " or ").concat(expected[1]);
    } else {
      return "of ".concat(thing, " ").concat(expected[0]);
    }
  } else {
    return "of ".concat(thing, " ").concat(String(expected));
  }
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/startsWith


function startsWith(str, search, pos) {
  return str.substr(!pos || pos < 0 ? 0 : +pos, search.length) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/endsWith


function endsWith(str, search, this_len) {
  if (this_len === undefined || this_len > str.length) {
    this_len = str.length;
  }

  return str.substring(this_len - search.length, this_len) === search;
} // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/includes


function includes(str, search, start) {
  if (typeof start !== 'number') {
    start = 0;
  }

  if (start + search.length > str.length) {
    return false;
  } else {
    return str.indexOf(search, start) !== -1;
  }
}

createErrorType('ERR_INVALID_OPT_VALUE', function (name, value) {
  return 'The value "' + value + '" is invalid for option "' + name + '"';
}, TypeError);
createErrorType('ERR_INVALID_ARG_TYPE', function (name, expected, actual) {
  // determiner: 'must be' or 'must not be'
  var determiner;

  if (typeof expected === 'string' && startsWith(expected, 'not ')) {
    determiner = 'must not be';
    expected = expected.replace(/^not /, '');
  } else {
    determiner = 'must be';
  }

  var msg;

  if (endsWith(name, ' argument')) {
    // For cases like 'first argument'
    msg = "The ".concat(name, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  } else {
    var type = includes(name, '.') ? 'property' : 'argument';
    msg = "The \"".concat(name, "\" ").concat(type, " ").concat(determiner, " ").concat(oneOf(expected, 'type'));
  }

  msg += ". Received type ".concat(typeof actual);
  return msg;
}, TypeError);
createErrorType('ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF');
createErrorType('ERR_METHOD_NOT_IMPLEMENTED', function (name) {
  return 'The ' + name + ' method is not implemented';
});
createErrorType('ERR_STREAM_PREMATURE_CLOSE', 'Premature close');
createErrorType('ERR_STREAM_DESTROYED', function (name) {
  return 'Cannot call ' + name + ' after a stream was destroyed';
});
createErrorType('ERR_MULTIPLE_CALLBACK', 'Callback called multiple times');
createErrorType('ERR_STREAM_CANNOT_PIPE', 'Cannot pipe, not readable');
createErrorType('ERR_STREAM_WRITE_AFTER_END', 'write after end');
createErrorType('ERR_STREAM_NULL_VALUES', 'May not write null values to stream', TypeError);
createErrorType('ERR_UNKNOWN_ENCODING', function (arg) {
  return 'Unknown encoding: ' + arg;
}, TypeError);
createErrorType('ERR_STREAM_UNSHIFT_AFTER_END_EVENT', 'stream.unshift() after end event');
module.exports.codes = codes;

},{}],68:[function(require,module,exports){
(function (process){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a duplex stream is just a stream that is both readable and writable.
// Since JS doesn't have multiple prototypal inheritance, this class
// prototypally inherits from Readable, and then parasitically from
// Writable.
'use strict';
/*<replacement>*/

var objectKeys = Object.keys || function (obj) {
  var keys = [];

  for (var key in obj) {
    keys.push(key);
  }

  return keys;
};
/*</replacement>*/


module.exports = Duplex;

var Readable = require('./_stream_readable');

var Writable = require('./_stream_writable');

require('inherits')(Duplex, Readable);

{
  // Allow the keys array to be GC'ed.
  var keys = objectKeys(Writable.prototype);

  for (var v = 0; v < keys.length; v++) {
    var method = keys[v];
    if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
  }
}

function Duplex(options) {
  if (!(this instanceof Duplex)) return new Duplex(options);
  Readable.call(this, options);
  Writable.call(this, options);
  this.allowHalfOpen = true;

  if (options) {
    if (options.readable === false) this.readable = false;
    if (options.writable === false) this.writable = false;

    if (options.allowHalfOpen === false) {
      this.allowHalfOpen = false;
      this.once('end', onend);
    }
  }
}

Object.defineProperty(Duplex.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
});
Object.defineProperty(Duplex.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});
Object.defineProperty(Duplex.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
}); // the no-half-open enforcer

function onend() {
  // If the writable side ended, then we're ok.
  if (this._writableState.ended) return; // no more data can be written.
  // But allow more writes to happen in this tick.

  process.nextTick(onEndNT, this);
}

function onEndNT(self) {
  self.end();
}

Object.defineProperty(Duplex.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined || this._writableState === undefined) {
      return false;
    }

    return this._readableState.destroyed && this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (this._readableState === undefined || this._writableState === undefined) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._readableState.destroyed = value;
    this._writableState.destroyed = value;
  }
});
}).call(this,require('_process'))
},{"./_stream_readable":70,"./_stream_writable":72,"_process":66,"inherits":65}],69:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a passthrough stream.
// basically just the most minimal sort of Transform stream.
// Every written chunk gets output as-is.
'use strict';

module.exports = PassThrough;

var Transform = require('./_stream_transform');

require('inherits')(PassThrough, Transform);

function PassThrough(options) {
  if (!(this instanceof PassThrough)) return new PassThrough(options);
  Transform.call(this, options);
}

PassThrough.prototype._transform = function (chunk, encoding, cb) {
  cb(null, chunk);
};
},{"./_stream_transform":71,"inherits":65}],70:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
'use strict';

module.exports = Readable;
/*<replacement>*/

var Duplex;
/*</replacement>*/

Readable.ReadableState = ReadableState;
/*<replacement>*/

var EE = require('events').EventEmitter;

var EElistenerCount = function EElistenerCount(emitter, type) {
  return emitter.listeners(type).length;
};
/*</replacement>*/

/*<replacement>*/


var Stream = require('./internal/streams/stream');
/*</replacement>*/


var Buffer = require('buffer').Buffer;

var OurUint8Array = global.Uint8Array || function () {};

function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}

function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}
/*<replacement>*/


var debugUtil = require('util');

var debug;

if (debugUtil && debugUtil.debuglog) {
  debug = debugUtil.debuglog('stream');
} else {
  debug = function debug() {};
}
/*</replacement>*/


var BufferList = require('./internal/streams/buffer_list');

var destroyImpl = require('./internal/streams/destroy');

var _require = require('./internal/streams/state'),
    getHighWaterMark = _require.getHighWaterMark;

var _require$codes = require('../errors').codes,
    ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
    ERR_STREAM_PUSH_AFTER_EOF = _require$codes.ERR_STREAM_PUSH_AFTER_EOF,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_STREAM_UNSHIFT_AFTER_END_EVENT = _require$codes.ERR_STREAM_UNSHIFT_AFTER_END_EVENT; // Lazy loaded to improve the startup performance.


var StringDecoder;
var createReadableStreamAsyncIterator;
var from;

require('inherits')(Readable, Stream);

var errorOrDestroy = destroyImpl.errorOrDestroy;
var kProxyEvents = ['error', 'close', 'destroy', 'pause', 'resume'];

function prependListener(emitter, event, fn) {
  // Sadly this is not cacheable as some libraries bundle their own
  // event emitter implementation with them.
  if (typeof emitter.prependListener === 'function') return emitter.prependListener(event, fn); // This is a hack to make sure that our error handler is attached before any
  // userland ones.  NEVER DO THIS. This is here only because this code needs
  // to continue to work with older versions of Node.js that do not include
  // the prependListener() method. The goal is to eventually remove this hack.

  if (!emitter._events || !emitter._events[event]) emitter.on(event, fn);else if (Array.isArray(emitter._events[event])) emitter._events[event].unshift(fn);else emitter._events[event] = [fn, emitter._events[event]];
}

function ReadableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {}; // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream.
  // These options can be provided separately as readableXXX and writableXXX.

  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex; // object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away

  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.readableObjectMode; // the point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"

  this.highWaterMark = getHighWaterMark(this, options, 'readableHighWaterMark', isDuplex); // A linked list is used to store data chunks instead of an array because the
  // linked list can remove elements from the beginning faster than
  // array.shift()

  this.buffer = new BufferList();
  this.length = 0;
  this.pipes = null;
  this.pipesCount = 0;
  this.flowing = null;
  this.ended = false;
  this.endEmitted = false;
  this.reading = false; // a flag to be able to tell if the event 'readable'/'data' is emitted
  // immediately, or on a later tick.  We set this to true at first, because
  // any actions that shouldn't happen until "later" should generally also
  // not happen before the first read call.

  this.sync = true; // whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.

  this.needReadable = false;
  this.emittedReadable = false;
  this.readableListening = false;
  this.resumeScheduled = false;
  this.paused = true; // Should close be emitted on destroy. Defaults to true.

  this.emitClose = options.emitClose !== false; // Should .destroy() be called after 'end' (and potentially 'finish')

  this.autoDestroy = !!options.autoDestroy; // has it been destroyed

  this.destroyed = false; // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.

  this.defaultEncoding = options.defaultEncoding || 'utf8'; // the number of writers that are awaiting a drain event in .pipe()s

  this.awaitDrain = 0; // if true, a maybeReadMore has been scheduled

  this.readingMore = false;
  this.decoder = null;
  this.encoding = null;

  if (options.encoding) {
    if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }
}

function Readable(options) {
  Duplex = Duplex || require('./_stream_duplex');
  if (!(this instanceof Readable)) return new Readable(options); // Checking for a Stream.Duplex instance is faster here instead of inside
  // the ReadableState constructor, at least with V8 6.5

  var isDuplex = this instanceof Duplex;
  this._readableState = new ReadableState(options, this, isDuplex); // legacy

  this.readable = true;

  if (options) {
    if (typeof options.read === 'function') this._read = options.read;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
  }

  Stream.call(this);
}

Object.defineProperty(Readable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._readableState === undefined) {
      return false;
    }

    return this._readableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._readableState) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._readableState.destroyed = value;
  }
});
Readable.prototype.destroy = destroyImpl.destroy;
Readable.prototype._undestroy = destroyImpl.undestroy;

Readable.prototype._destroy = function (err, cb) {
  cb(err);
}; // Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.


Readable.prototype.push = function (chunk, encoding) {
  var state = this._readableState;
  var skipChunkCheck;

  if (!state.objectMode) {
    if (typeof chunk === 'string') {
      encoding = encoding || state.defaultEncoding;

      if (encoding !== state.encoding) {
        chunk = Buffer.from(chunk, encoding);
        encoding = '';
      }

      skipChunkCheck = true;
    }
  } else {
    skipChunkCheck = true;
  }

  return readableAddChunk(this, chunk, encoding, false, skipChunkCheck);
}; // Unshift should *always* be something directly out of read()


Readable.prototype.unshift = function (chunk) {
  return readableAddChunk(this, chunk, null, true, false);
};

function readableAddChunk(stream, chunk, encoding, addToFront, skipChunkCheck) {
  debug('readableAddChunk', chunk);
  var state = stream._readableState;

  if (chunk === null) {
    state.reading = false;
    onEofChunk(stream, state);
  } else {
    var er;
    if (!skipChunkCheck) er = chunkInvalid(state, chunk);

    if (er) {
      errorOrDestroy(stream, er);
    } else if (state.objectMode || chunk && chunk.length > 0) {
      if (typeof chunk !== 'string' && !state.objectMode && Object.getPrototypeOf(chunk) !== Buffer.prototype) {
        chunk = _uint8ArrayToBuffer(chunk);
      }

      if (addToFront) {
        if (state.endEmitted) errorOrDestroy(stream, new ERR_STREAM_UNSHIFT_AFTER_END_EVENT());else addChunk(stream, state, chunk, true);
      } else if (state.ended) {
        errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
      } else if (state.destroyed) {
        return false;
      } else {
        state.reading = false;

        if (state.decoder && !encoding) {
          chunk = state.decoder.write(chunk);
          if (state.objectMode || chunk.length !== 0) addChunk(stream, state, chunk, false);else maybeReadMore(stream, state);
        } else {
          addChunk(stream, state, chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
      maybeReadMore(stream, state);
    }
  } // We can push more data if we are below the highWaterMark.
  // Also, if we have no data yet, we can stand some more bytes.
  // This is to work around cases where hwm=0, such as the repl.


  return !state.ended && (state.length < state.highWaterMark || state.length === 0);
}

function addChunk(stream, state, chunk, addToFront) {
  if (state.flowing && state.length === 0 && !state.sync) {
    state.awaitDrain = 0;
    stream.emit('data', chunk);
  } else {
    // update the buffer info.
    state.length += state.objectMode ? 1 : chunk.length;
    if (addToFront) state.buffer.unshift(chunk);else state.buffer.push(chunk);
    if (state.needReadable) emitReadable(stream);
  }

  maybeReadMore(stream, state);
}

function chunkInvalid(state, chunk) {
  var er;

  if (!_isUint8Array(chunk) && typeof chunk !== 'string' && chunk !== undefined && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer', 'Uint8Array'], chunk);
  }

  return er;
}

Readable.prototype.isPaused = function () {
  return this._readableState.flowing === false;
}; // backwards compatibility.


Readable.prototype.setEncoding = function (enc) {
  if (!StringDecoder) StringDecoder = require('string_decoder/').StringDecoder;
  var decoder = new StringDecoder(enc);
  this._readableState.decoder = decoder; // If setEncoding(null), decoder.encoding equals utf8

  this._readableState.encoding = this._readableState.decoder.encoding; // Iterate over current buffer to convert already stored Buffers:

  var p = this._readableState.buffer.head;
  var content = '';

  while (p !== null) {
    content += decoder.write(p.data);
    p = p.next;
  }

  this._readableState.buffer.clear();

  if (content !== '') this._readableState.buffer.push(content);
  this._readableState.length = content.length;
  return this;
}; // Don't raise the hwm > 1GB


var MAX_HWM = 0x40000000;

function computeNewHighWaterMark(n) {
  if (n >= MAX_HWM) {
    // TODO(ronag): Throw ERR_VALUE_OUT_OF_RANGE.
    n = MAX_HWM;
  } else {
    // Get the next highest power of 2 to prevent increasing hwm excessively in
    // tiny amounts
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }

  return n;
} // This function is designed to be inlinable, so please take care when making
// changes to the function body.


function howMuchToRead(n, state) {
  if (n <= 0 || state.length === 0 && state.ended) return 0;
  if (state.objectMode) return 1;

  if (n !== n) {
    // Only flow one buffer at a time
    if (state.flowing && state.length) return state.buffer.head.data.length;else return state.length;
  } // If we're asking for more than the current hwm, then raise the hwm.


  if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
  if (n <= state.length) return n; // Don't have enough

  if (!state.ended) {
    state.needReadable = true;
    return 0;
  }

  return state.length;
} // you can override either this method, or the async _read(n) below.


Readable.prototype.read = function (n) {
  debug('read', n);
  n = parseInt(n, 10);
  var state = this._readableState;
  var nOrig = n;
  if (n !== 0) state.emittedReadable = false; // if we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.

  if (n === 0 && state.needReadable && ((state.highWaterMark !== 0 ? state.length >= state.highWaterMark : state.length > 0) || state.ended)) {
    debug('read: emitReadable', state.length, state.ended);
    if (state.length === 0 && state.ended) endReadable(this);else emitReadable(this);
    return null;
  }

  n = howMuchToRead(n, state); // if we've ended, and we're now clear, then finish it up.

  if (n === 0 && state.ended) {
    if (state.length === 0) endReadable(this);
    return null;
  } // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.
  // if we need a readable event, then we need to do some reading.


  var doRead = state.needReadable;
  debug('need readable', doRead); // if we currently have less than the highWaterMark, then also read some

  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug('length less than watermark', doRead);
  } // however, if we've ended, then there's no point, and if we're already
  // reading, then it's unnecessary.


  if (state.ended || state.reading) {
    doRead = false;
    debug('reading or ended', doRead);
  } else if (doRead) {
    debug('do read');
    state.reading = true;
    state.sync = true; // if the length is currently zero, then we *need* a readable event.

    if (state.length === 0) state.needReadable = true; // call internal read method

    this._read(state.highWaterMark);

    state.sync = false; // If _read pushed data synchronously, then `reading` will be false,
    // and we need to re-evaluate how much data we can return to the user.

    if (!state.reading) n = howMuchToRead(nOrig, state);
  }

  var ret;
  if (n > 0) ret = fromList(n, state);else ret = null;

  if (ret === null) {
    state.needReadable = state.length <= state.highWaterMark;
    n = 0;
  } else {
    state.length -= n;
    state.awaitDrain = 0;
  }

  if (state.length === 0) {
    // If we have nothing in the buffer, then we want to know
    // as soon as we *do* get something into the buffer.
    if (!state.ended) state.needReadable = true; // If we tried to read() past the EOF, then emit end on the next tick.

    if (nOrig !== n && state.ended) endReadable(this);
  }

  if (ret !== null) this.emit('data', ret);
  return ret;
};

function onEofChunk(stream, state) {
  debug('onEofChunk');
  if (state.ended) return;

  if (state.decoder) {
    var chunk = state.decoder.end();

    if (chunk && chunk.length) {
      state.buffer.push(chunk);
      state.length += state.objectMode ? 1 : chunk.length;
    }
  }

  state.ended = true;

  if (state.sync) {
    // if we are sync, wait until next tick to emit the data.
    // Otherwise we risk emitting data in the flow()
    // the readable code triggers during a read() call
    emitReadable(stream);
  } else {
    // emit 'readable' now to make sure it gets picked up.
    state.needReadable = false;

    if (!state.emittedReadable) {
      state.emittedReadable = true;
      emitReadable_(stream);
    }
  }
} // Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.


function emitReadable(stream) {
  var state = stream._readableState;
  debug('emitReadable', state.needReadable, state.emittedReadable);
  state.needReadable = false;

  if (!state.emittedReadable) {
    debug('emitReadable', state.flowing);
    state.emittedReadable = true;
    process.nextTick(emitReadable_, stream);
  }
}

function emitReadable_(stream) {
  var state = stream._readableState;
  debug('emitReadable_', state.destroyed, state.length, state.ended);

  if (!state.destroyed && (state.length || state.ended)) {
    stream.emit('readable');
    state.emittedReadable = false;
  } // The stream needs another readable event if
  // 1. It is not flowing, as the flow mechanism will take
  //    care of it.
  // 2. It is not ended.
  // 3. It is below the highWaterMark, so we can schedule
  //    another readable later.


  state.needReadable = !state.flowing && !state.ended && state.length <= state.highWaterMark;
  flow(stream);
} // at this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.


function maybeReadMore(stream, state) {
  if (!state.readingMore) {
    state.readingMore = true;
    process.nextTick(maybeReadMore_, stream, state);
  }
}

function maybeReadMore_(stream, state) {
  // Attempt to read more data if we should.
  //
  // The conditions for reading more data are (one of):
  // - Not enough data buffered (state.length < state.highWaterMark). The loop
  //   is responsible for filling the buffer with enough data if such data
  //   is available. If highWaterMark is 0 and we are not in the flowing mode
  //   we should _not_ attempt to buffer any extra data. We'll get more data
  //   when the stream consumer calls read() instead.
  // - No data in the buffer, and the stream is in flowing mode. In this mode
  //   the loop below is responsible for ensuring read() is called. Failing to
  //   call read here would abort the flow and there's no other mechanism for
  //   continuing the flow if the stream consumer has just subscribed to the
  //   'data' event.
  //
  // In addition to the above conditions to keep reading data, the following
  // conditions prevent the data from being read:
  // - The stream has ended (state.ended).
  // - There is already a pending 'read' operation (state.reading). This is a
  //   case where the the stream has called the implementation defined _read()
  //   method, but they are processing the call asynchronously and have _not_
  //   called push() with new data. In this case we skip performing more
  //   read()s. The execution ends in this method again after the _read() ends
  //   up calling push() with more data.
  while (!state.reading && !state.ended && (state.length < state.highWaterMark || state.flowing && state.length === 0)) {
    var len = state.length;
    debug('maybeReadMore read 0');
    stream.read(0);
    if (len === state.length) // didn't get any data, stop spinning.
      break;
  }

  state.readingMore = false;
} // abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.


Readable.prototype._read = function (n) {
  errorOrDestroy(this, new ERR_METHOD_NOT_IMPLEMENTED('_read()'));
};

Readable.prototype.pipe = function (dest, pipeOpts) {
  var src = this;
  var state = this._readableState;

  switch (state.pipesCount) {
    case 0:
      state.pipes = dest;
      break;

    case 1:
      state.pipes = [state.pipes, dest];
      break;

    default:
      state.pipes.push(dest);
      break;
  }

  state.pipesCount += 1;
  debug('pipe count=%d opts=%j', state.pipesCount, pipeOpts);
  var doEnd = (!pipeOpts || pipeOpts.end !== false) && dest !== process.stdout && dest !== process.stderr;
  var endFn = doEnd ? onend : unpipe;
  if (state.endEmitted) process.nextTick(endFn);else src.once('end', endFn);
  dest.on('unpipe', onunpipe);

  function onunpipe(readable, unpipeInfo) {
    debug('onunpipe');

    if (readable === src) {
      if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
  }

  function onend() {
    debug('onend');
    dest.end();
  } // when the dest drains, it reduces the awaitDrain counter
  // on the source.  This would be more elegant with a .once()
  // handler in flow(), but adding and removing repeatedly is
  // too slow.


  var ondrain = pipeOnDrain(src);
  dest.on('drain', ondrain);
  var cleanedUp = false;

  function cleanup() {
    debug('cleanup'); // cleanup event handlers once the pipe is broken

    dest.removeListener('close', onclose);
    dest.removeListener('finish', onfinish);
    dest.removeListener('drain', ondrain);
    dest.removeListener('error', onerror);
    dest.removeListener('unpipe', onunpipe);
    src.removeListener('end', onend);
    src.removeListener('end', unpipe);
    src.removeListener('data', ondata);
    cleanedUp = true; // if the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.

    if (state.awaitDrain && (!dest._writableState || dest._writableState.needDrain)) ondrain();
  }

  src.on('data', ondata);

  function ondata(chunk) {
    debug('ondata');
    var ret = dest.write(chunk);
    debug('dest.write', ret);

    if (ret === false) {
      // If the user unpiped during `dest.write()`, it is possible
      // to get stuck in a permanently paused state if that write
      // also returned false.
      // => Check whether `dest` is still a piping destination.
      if ((state.pipesCount === 1 && state.pipes === dest || state.pipesCount > 1 && indexOf(state.pipes, dest) !== -1) && !cleanedUp) {
        debug('false write response, pause', state.awaitDrain);
        state.awaitDrain++;
      }

      src.pause();
    }
  } // if the dest has an error, then stop piping into it.
  // however, don't suppress the throwing behavior for this.


  function onerror(er) {
    debug('onerror', er);
    unpipe();
    dest.removeListener('error', onerror);
    if (EElistenerCount(dest, 'error') === 0) errorOrDestroy(dest, er);
  } // Make sure our error handler is attached before userland ones.


  prependListener(dest, 'error', onerror); // Both close and finish should trigger unpipe, but only once.

  function onclose() {
    dest.removeListener('finish', onfinish);
    unpipe();
  }

  dest.once('close', onclose);

  function onfinish() {
    debug('onfinish');
    dest.removeListener('close', onclose);
    unpipe();
  }

  dest.once('finish', onfinish);

  function unpipe() {
    debug('unpipe');
    src.unpipe(dest);
  } // tell the dest that it's being piped to


  dest.emit('pipe', src); // start the flow if it hasn't been started already.

  if (!state.flowing) {
    debug('pipe resume');
    src.resume();
  }

  return dest;
};

function pipeOnDrain(src) {
  return function pipeOnDrainFunctionResult() {
    var state = src._readableState;
    debug('pipeOnDrain', state.awaitDrain);
    if (state.awaitDrain) state.awaitDrain--;

    if (state.awaitDrain === 0 && EElistenerCount(src, 'data')) {
      state.flowing = true;
      flow(src);
    }
  };
}

Readable.prototype.unpipe = function (dest) {
  var state = this._readableState;
  var unpipeInfo = {
    hasUnpiped: false
  }; // if we're not piping anywhere, then do nothing.

  if (state.pipesCount === 0) return this; // just one destination.  most common case.

  if (state.pipesCount === 1) {
    // passed in one, but it's not the right one.
    if (dest && dest !== state.pipes) return this;
    if (!dest) dest = state.pipes; // got a match.

    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;
    if (dest) dest.emit('unpipe', this, unpipeInfo);
    return this;
  } // slow case. multiple pipe destinations.


  if (!dest) {
    // remove all.
    var dests = state.pipes;
    var len = state.pipesCount;
    state.pipes = null;
    state.pipesCount = 0;
    state.flowing = false;

    for (var i = 0; i < len; i++) {
      dests[i].emit('unpipe', this, {
        hasUnpiped: false
      });
    }

    return this;
  } // try to find the right one.


  var index = indexOf(state.pipes, dest);
  if (index === -1) return this;
  state.pipes.splice(index, 1);
  state.pipesCount -= 1;
  if (state.pipesCount === 1) state.pipes = state.pipes[0];
  dest.emit('unpipe', this, unpipeInfo);
  return this;
}; // set up data events if they are asked for
// Ensure readable listeners eventually get something


Readable.prototype.on = function (ev, fn) {
  var res = Stream.prototype.on.call(this, ev, fn);
  var state = this._readableState;

  if (ev === 'data') {
    // update readableListening so that resume() may be a no-op
    // a few lines down. This is needed to support once('readable').
    state.readableListening = this.listenerCount('readable') > 0; // Try start flowing on next tick if stream isn't explicitly paused

    if (state.flowing !== false) this.resume();
  } else if (ev === 'readable') {
    if (!state.endEmitted && !state.readableListening) {
      state.readableListening = state.needReadable = true;
      state.flowing = false;
      state.emittedReadable = false;
      debug('on readable', state.length, state.reading);

      if (state.length) {
        emitReadable(this);
      } else if (!state.reading) {
        process.nextTick(nReadingNextTick, this);
      }
    }
  }

  return res;
};

Readable.prototype.addListener = Readable.prototype.on;

Readable.prototype.removeListener = function (ev, fn) {
  var res = Stream.prototype.removeListener.call(this, ev, fn);

  if (ev === 'readable') {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }

  return res;
};

Readable.prototype.removeAllListeners = function (ev) {
  var res = Stream.prototype.removeAllListeners.apply(this, arguments);

  if (ev === 'readable' || ev === undefined) {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    process.nextTick(updateReadableListening, this);
  }

  return res;
};

function updateReadableListening(self) {
  var state = self._readableState;
  state.readableListening = self.listenerCount('readable') > 0;

  if (state.resumeScheduled && !state.paused) {
    // flowing needs to be set to true now, otherwise
    // the upcoming resume will not flow.
    state.flowing = true; // crude way to check if we should resume
  } else if (self.listenerCount('data') > 0) {
    self.resume();
  }
}

function nReadingNextTick(self) {
  debug('readable nexttick read 0');
  self.read(0);
} // pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.


Readable.prototype.resume = function () {
  var state = this._readableState;

  if (!state.flowing) {
    debug('resume'); // we flow only if there is no one listening
    // for readable, but we still have to call
    // resume()

    state.flowing = !state.readableListening;
    resume(this, state);
  }

  state.paused = false;
  return this;
};

function resume(stream, state) {
  if (!state.resumeScheduled) {
    state.resumeScheduled = true;
    process.nextTick(resume_, stream, state);
  }
}

function resume_(stream, state) {
  debug('resume', state.reading);

  if (!state.reading) {
    stream.read(0);
  }

  state.resumeScheduled = false;
  stream.emit('resume');
  flow(stream);
  if (state.flowing && !state.reading) stream.read(0);
}

Readable.prototype.pause = function () {
  debug('call pause flowing=%j', this._readableState.flowing);

  if (this._readableState.flowing !== false) {
    debug('pause');
    this._readableState.flowing = false;
    this.emit('pause');
  }

  this._readableState.paused = true;
  return this;
};

function flow(stream) {
  var state = stream._readableState;
  debug('flow', state.flowing);

  while (state.flowing && stream.read() !== null) {
    ;
  }
} // wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.


Readable.prototype.wrap = function (stream) {
  var _this = this;

  var state = this._readableState;
  var paused = false;
  stream.on('end', function () {
    debug('wrapped end');

    if (state.decoder && !state.ended) {
      var chunk = state.decoder.end();
      if (chunk && chunk.length) _this.push(chunk);
    }

    _this.push(null);
  });
  stream.on('data', function (chunk) {
    debug('wrapped data');
    if (state.decoder) chunk = state.decoder.write(chunk); // don't skip over falsy values in objectMode

    if (state.objectMode && (chunk === null || chunk === undefined)) return;else if (!state.objectMode && (!chunk || !chunk.length)) return;

    var ret = _this.push(chunk);

    if (!ret) {
      paused = true;
      stream.pause();
    }
  }); // proxy all the other methods.
  // important when wrapping filters and duplexes.

  for (var i in stream) {
    if (this[i] === undefined && typeof stream[i] === 'function') {
      this[i] = function methodWrap(method) {
        return function methodWrapReturnFunction() {
          return stream[method].apply(stream, arguments);
        };
      }(i);
    }
  } // proxy certain important events.


  for (var n = 0; n < kProxyEvents.length; n++) {
    stream.on(kProxyEvents[n], this.emit.bind(this, kProxyEvents[n]));
  } // when we try to consume some more bytes, simply unpause the
  // underlying stream.


  this._read = function (n) {
    debug('wrapped _read', n);

    if (paused) {
      paused = false;
      stream.resume();
    }
  };

  return this;
};

if (typeof Symbol === 'function') {
  Readable.prototype[Symbol.asyncIterator] = function () {
    if (createReadableStreamAsyncIterator === undefined) {
      createReadableStreamAsyncIterator = require('./internal/streams/async_iterator');
    }

    return createReadableStreamAsyncIterator(this);
  };
}

Object.defineProperty(Readable.prototype, 'readableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.highWaterMark;
  }
});
Object.defineProperty(Readable.prototype, 'readableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState && this._readableState.buffer;
  }
});
Object.defineProperty(Readable.prototype, 'readableFlowing', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.flowing;
  },
  set: function set(state) {
    if (this._readableState) {
      this._readableState.flowing = state;
    }
  }
}); // exposed for testing purposes only.

Readable._fromList = fromList;
Object.defineProperty(Readable.prototype, 'readableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._readableState.length;
  }
}); // Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.

function fromList(n, state) {
  // nothing buffered
  if (state.length === 0) return null;
  var ret;
  if (state.objectMode) ret = state.buffer.shift();else if (!n || n >= state.length) {
    // read it all, truncate the list
    if (state.decoder) ret = state.buffer.join('');else if (state.buffer.length === 1) ret = state.buffer.first();else ret = state.buffer.concat(state.length);
    state.buffer.clear();
  } else {
    // read part of list
    ret = state.buffer.consume(n, state.decoder);
  }
  return ret;
}

function endReadable(stream) {
  var state = stream._readableState;
  debug('endReadable', state.endEmitted);

  if (!state.endEmitted) {
    state.ended = true;
    process.nextTick(endReadableNT, state, stream);
  }
}

function endReadableNT(state, stream) {
  debug('endReadableNT', state.endEmitted, state.length); // Check that we didn't get one last unshift.

  if (!state.endEmitted && state.length === 0) {
    state.endEmitted = true;
    stream.readable = false;
    stream.emit('end');

    if (state.autoDestroy) {
      // In case of duplex streams we need a way to detect
      // if the writable side is ready for autoDestroy as well
      var wState = stream._writableState;

      if (!wState || wState.autoDestroy && wState.finished) {
        stream.destroy();
      }
    }
  }
}

if (typeof Symbol === 'function') {
  Readable.from = function (iterable, opts) {
    if (from === undefined) {
      from = require('./internal/streams/from');
    }

    return from(Readable, iterable, opts);
  };
}

function indexOf(xs, x) {
  for (var i = 0, l = xs.length; i < l; i++) {
    if (xs[i] === x) return i;
  }

  return -1;
}
}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../errors":67,"./_stream_duplex":68,"./internal/streams/async_iterator":73,"./internal/streams/buffer_list":74,"./internal/streams/destroy":75,"./internal/streams/from":77,"./internal/streams/state":79,"./internal/streams/stream":80,"_process":66,"buffer":62,"events":63,"inherits":65,"string_decoder/":94,"util":60}],71:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.
'use strict';

module.exports = Transform;

var _require$codes = require('../errors').codes,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
    ERR_TRANSFORM_ALREADY_TRANSFORMING = _require$codes.ERR_TRANSFORM_ALREADY_TRANSFORMING,
    ERR_TRANSFORM_WITH_LENGTH_0 = _require$codes.ERR_TRANSFORM_WITH_LENGTH_0;

var Duplex = require('./_stream_duplex');

require('inherits')(Transform, Duplex);

function afterTransform(er, data) {
  var ts = this._transformState;
  ts.transforming = false;
  var cb = ts.writecb;

  if (cb === null) {
    return this.emit('error', new ERR_MULTIPLE_CALLBACK());
  }

  ts.writechunk = null;
  ts.writecb = null;
  if (data != null) // single equals check for both `null` and `undefined`
    this.push(data);
  cb(er);
  var rs = this._readableState;
  rs.reading = false;

  if (rs.needReadable || rs.length < rs.highWaterMark) {
    this._read(rs.highWaterMark);
  }
}

function Transform(options) {
  if (!(this instanceof Transform)) return new Transform(options);
  Duplex.call(this, options);
  this._transformState = {
    afterTransform: afterTransform.bind(this),
    needTransform: false,
    transforming: false,
    writecb: null,
    writechunk: null,
    writeencoding: null
  }; // start out asking for a readable event once data is transformed.

  this._readableState.needReadable = true; // we have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.

  this._readableState.sync = false;

  if (options) {
    if (typeof options.transform === 'function') this._transform = options.transform;
    if (typeof options.flush === 'function') this._flush = options.flush;
  } // When the writable side finishes, then flush out anything remaining.


  this.on('prefinish', prefinish);
}

function prefinish() {
  var _this = this;

  if (typeof this._flush === 'function' && !this._readableState.destroyed) {
    this._flush(function (er, data) {
      done(_this, er, data);
    });
  } else {
    done(this, null, null);
  }
}

Transform.prototype.push = function (chunk, encoding) {
  this._transformState.needTransform = false;
  return Duplex.prototype.push.call(this, chunk, encoding);
}; // This is the part where you do stuff!
// override this function in implementation classes.
// 'chunk' is an input chunk.
//
// Call `push(newChunk)` to pass along transformed output
// to the readable side.  You may call 'push' zero or more times.
//
// Call `cb(err)` when you are done with this chunk.  If you pass
// an error, then that'll put the hurt on the whole operation.  If you
// never call cb(), then you'll never get another chunk.


Transform.prototype._transform = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_transform()'));
};

Transform.prototype._write = function (chunk, encoding, cb) {
  var ts = this._transformState;
  ts.writecb = cb;
  ts.writechunk = chunk;
  ts.writeencoding = encoding;

  if (!ts.transforming) {
    var rs = this._readableState;
    if (ts.needTransform || rs.needReadable || rs.length < rs.highWaterMark) this._read(rs.highWaterMark);
  }
}; // Doesn't matter what the args are here.
// _transform does all the work.
// That we got here means that the readable side wants more data.


Transform.prototype._read = function (n) {
  var ts = this._transformState;

  if (ts.writechunk !== null && !ts.transforming) {
    ts.transforming = true;

    this._transform(ts.writechunk, ts.writeencoding, ts.afterTransform);
  } else {
    // mark that we need a transform, so that any data that comes in
    // will get processed, now that we've asked for it.
    ts.needTransform = true;
  }
};

Transform.prototype._destroy = function (err, cb) {
  Duplex.prototype._destroy.call(this, err, function (err2) {
    cb(err2);
  });
};

function done(stream, er, data) {
  if (er) return stream.emit('error', er);
  if (data != null) // single equals check for both `null` and `undefined`
    stream.push(data); // TODO(BridgeAR): Write a test for these two error cases
  // if there's nothing in the write buffer, then that means
  // that nothing more will ever be provided

  if (stream._writableState.length) throw new ERR_TRANSFORM_WITH_LENGTH_0();
  if (stream._transformState.transforming) throw new ERR_TRANSFORM_ALREADY_TRANSFORMING();
  return stream.push(null);
}
},{"../errors":67,"./_stream_duplex":68,"inherits":65}],72:[function(require,module,exports){
(function (process,global){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.
'use strict';

module.exports = Writable;
/* <replacement> */

function WriteReq(chunk, encoding, cb) {
  this.chunk = chunk;
  this.encoding = encoding;
  this.callback = cb;
  this.next = null;
} // It seems a linked list but it is not
// there will be only 2 of these for each stream


function CorkedRequest(state) {
  var _this = this;

  this.next = null;
  this.entry = null;

  this.finish = function () {
    onCorkedFinish(_this, state);
  };
}
/* </replacement> */

/*<replacement>*/


var Duplex;
/*</replacement>*/

Writable.WritableState = WritableState;
/*<replacement>*/

var internalUtil = {
  deprecate: require('util-deprecate')
};
/*</replacement>*/

/*<replacement>*/

var Stream = require('./internal/streams/stream');
/*</replacement>*/


var Buffer = require('buffer').Buffer;

var OurUint8Array = global.Uint8Array || function () {};

function _uint8ArrayToBuffer(chunk) {
  return Buffer.from(chunk);
}

function _isUint8Array(obj) {
  return Buffer.isBuffer(obj) || obj instanceof OurUint8Array;
}

var destroyImpl = require('./internal/streams/destroy');

var _require = require('./internal/streams/state'),
    getHighWaterMark = _require.getHighWaterMark;

var _require$codes = require('../errors').codes,
    ERR_INVALID_ARG_TYPE = _require$codes.ERR_INVALID_ARG_TYPE,
    ERR_METHOD_NOT_IMPLEMENTED = _require$codes.ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK = _require$codes.ERR_MULTIPLE_CALLBACK,
    ERR_STREAM_CANNOT_PIPE = _require$codes.ERR_STREAM_CANNOT_PIPE,
    ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED,
    ERR_STREAM_NULL_VALUES = _require$codes.ERR_STREAM_NULL_VALUES,
    ERR_STREAM_WRITE_AFTER_END = _require$codes.ERR_STREAM_WRITE_AFTER_END,
    ERR_UNKNOWN_ENCODING = _require$codes.ERR_UNKNOWN_ENCODING;

var errorOrDestroy = destroyImpl.errorOrDestroy;

require('inherits')(Writable, Stream);

function nop() {}

function WritableState(options, stream, isDuplex) {
  Duplex = Duplex || require('./_stream_duplex');
  options = options || {}; // Duplex streams are both readable and writable, but share
  // the same options object.
  // However, some cases require setting options to different
  // values for the readable and the writable sides of the duplex stream,
  // e.g. options.readableObjectMode vs. options.writableObjectMode, etc.

  if (typeof isDuplex !== 'boolean') isDuplex = stream instanceof Duplex; // object stream flag to indicate whether or not this stream
  // contains buffers or objects.

  this.objectMode = !!options.objectMode;
  if (isDuplex) this.objectMode = this.objectMode || !!options.writableObjectMode; // the point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write()

  this.highWaterMark = getHighWaterMark(this, options, 'writableHighWaterMark', isDuplex); // if _final has been called

  this.finalCalled = false; // drain event flag.

  this.needDrain = false; // at the start of calling end()

  this.ending = false; // when end() has been called, and returned

  this.ended = false; // when 'finish' is emitted

  this.finished = false; // has it been destroyed

  this.destroyed = false; // should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.

  var noDecode = options.decodeStrings === false;
  this.decodeStrings = !noDecode; // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.

  this.defaultEncoding = options.defaultEncoding || 'utf8'; // not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.

  this.length = 0; // a flag to see when we're in the middle of a write.

  this.writing = false; // when true all writes will be buffered until .uncork() call

  this.corked = 0; // a flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.

  this.sync = true; // a flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.

  this.bufferProcessing = false; // the callback that's passed to _write(chunk,cb)

  this.onwrite = function (er) {
    onwrite(stream, er);
  }; // the callback that the user supplies to write(chunk,encoding,cb)


  this.writecb = null; // the amount that is being written when _write is called.

  this.writelen = 0;
  this.bufferedRequest = null;
  this.lastBufferedRequest = null; // number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted

  this.pendingcb = 0; // emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams

  this.prefinished = false; // True if the error was already emitted and should not be thrown again

  this.errorEmitted = false; // Should close be emitted on destroy. Defaults to true.

  this.emitClose = options.emitClose !== false; // Should .destroy() be called after 'finish' (and potentially 'end')

  this.autoDestroy = !!options.autoDestroy; // count buffered requests

  this.bufferedRequestCount = 0; // allocate the first CorkedRequest, there is always
  // one allocated and free to use, and we maintain at most two

  this.corkedRequestsFree = new CorkedRequest(this);
}

WritableState.prototype.getBuffer = function getBuffer() {
  var current = this.bufferedRequest;
  var out = [];

  while (current) {
    out.push(current);
    current = current.next;
  }

  return out;
};

(function () {
  try {
    Object.defineProperty(WritableState.prototype, 'buffer', {
      get: internalUtil.deprecate(function writableStateBufferGetter() {
        return this.getBuffer();
      }, '_writableState.buffer is deprecated. Use _writableState.getBuffer ' + 'instead.', 'DEP0003')
    });
  } catch (_) {}
})(); // Test _writableState for inheritance to account for Duplex streams,
// whose prototype chain only points to Readable.


var realHasInstance;

if (typeof Symbol === 'function' && Symbol.hasInstance && typeof Function.prototype[Symbol.hasInstance] === 'function') {
  realHasInstance = Function.prototype[Symbol.hasInstance];
  Object.defineProperty(Writable, Symbol.hasInstance, {
    value: function value(object) {
      if (realHasInstance.call(this, object)) return true;
      if (this !== Writable) return false;
      return object && object._writableState instanceof WritableState;
    }
  });
} else {
  realHasInstance = function realHasInstance(object) {
    return object instanceof this;
  };
}

function Writable(options) {
  Duplex = Duplex || require('./_stream_duplex'); // Writable ctor is applied to Duplexes, too.
  // `realHasInstance` is necessary because using plain `instanceof`
  // would return false, as no `_writableState` property is attached.
  // Trying to use the custom `instanceof` for Writable here will also break the
  // Node.js LazyTransform implementation, which has a non-trivial getter for
  // `_writableState` that would lead to infinite recursion.
  // Checking for a Stream.Duplex instance is faster here instead of inside
  // the WritableState constructor, at least with V8 6.5

  var isDuplex = this instanceof Duplex;
  if (!isDuplex && !realHasInstance.call(Writable, this)) return new Writable(options);
  this._writableState = new WritableState(options, this, isDuplex); // legacy.

  this.writable = true;

  if (options) {
    if (typeof options.write === 'function') this._write = options.write;
    if (typeof options.writev === 'function') this._writev = options.writev;
    if (typeof options.destroy === 'function') this._destroy = options.destroy;
    if (typeof options.final === 'function') this._final = options.final;
  }

  Stream.call(this);
} // Otherwise people can pipe Writable streams, which is just wrong.


Writable.prototype.pipe = function () {
  errorOrDestroy(this, new ERR_STREAM_CANNOT_PIPE());
};

function writeAfterEnd(stream, cb) {
  var er = new ERR_STREAM_WRITE_AFTER_END(); // TODO: defer error events consistently everywhere, not just the cb

  errorOrDestroy(stream, er);
  process.nextTick(cb, er);
} // Checks that a user-supplied chunk is valid, especially for the particular
// mode the stream is in. Currently this means that `null` is never accepted
// and undefined/non-string values are only allowed in object mode.


function validChunk(stream, state, chunk, cb) {
  var er;

  if (chunk === null) {
    er = new ERR_STREAM_NULL_VALUES();
  } else if (typeof chunk !== 'string' && !state.objectMode) {
    er = new ERR_INVALID_ARG_TYPE('chunk', ['string', 'Buffer'], chunk);
  }

  if (er) {
    errorOrDestroy(stream, er);
    process.nextTick(cb, er);
    return false;
  }

  return true;
}

Writable.prototype.write = function (chunk, encoding, cb) {
  var state = this._writableState;
  var ret = false;

  var isBuf = !state.objectMode && _isUint8Array(chunk);

  if (isBuf && !Buffer.isBuffer(chunk)) {
    chunk = _uint8ArrayToBuffer(chunk);
  }

  if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (isBuf) encoding = 'buffer';else if (!encoding) encoding = state.defaultEncoding;
  if (typeof cb !== 'function') cb = nop;
  if (state.ending) writeAfterEnd(this, cb);else if (isBuf || validChunk(this, state, chunk, cb)) {
    state.pendingcb++;
    ret = writeOrBuffer(this, state, isBuf, chunk, encoding, cb);
  }
  return ret;
};

Writable.prototype.cork = function () {
  this._writableState.corked++;
};

Writable.prototype.uncork = function () {
  var state = this._writableState;

  if (state.corked) {
    state.corked--;
    if (!state.writing && !state.corked && !state.bufferProcessing && state.bufferedRequest) clearBuffer(this, state);
  }
};

Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === 'string') encoding = encoding.toLowerCase();
  if (!(['hex', 'utf8', 'utf-8', 'ascii', 'binary', 'base64', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'raw'].indexOf((encoding + '').toLowerCase()) > -1)) throw new ERR_UNKNOWN_ENCODING(encoding);
  this._writableState.defaultEncoding = encoding;
  return this;
};

Object.defineProperty(Writable.prototype, 'writableBuffer', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState && this._writableState.getBuffer();
  }
});

function decodeChunk(state, chunk, encoding) {
  if (!state.objectMode && state.decodeStrings !== false && typeof chunk === 'string') {
    chunk = Buffer.from(chunk, encoding);
  }

  return chunk;
}

Object.defineProperty(Writable.prototype, 'writableHighWaterMark', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.highWaterMark;
  }
}); // if we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.

function writeOrBuffer(stream, state, isBuf, chunk, encoding, cb) {
  if (!isBuf) {
    var newChunk = decodeChunk(state, chunk, encoding);

    if (chunk !== newChunk) {
      isBuf = true;
      encoding = 'buffer';
      chunk = newChunk;
    }
  }

  var len = state.objectMode ? 1 : chunk.length;
  state.length += len;
  var ret = state.length < state.highWaterMark; // we must ensure that previous needDrain will not be reset to false.

  if (!ret) state.needDrain = true;

  if (state.writing || state.corked) {
    var last = state.lastBufferedRequest;
    state.lastBufferedRequest = {
      chunk: chunk,
      encoding: encoding,
      isBuf: isBuf,
      callback: cb,
      next: null
    };

    if (last) {
      last.next = state.lastBufferedRequest;
    } else {
      state.bufferedRequest = state.lastBufferedRequest;
    }

    state.bufferedRequestCount += 1;
  } else {
    doWrite(stream, state, false, len, chunk, encoding, cb);
  }

  return ret;
}

function doWrite(stream, state, writev, len, chunk, encoding, cb) {
  state.writelen = len;
  state.writecb = cb;
  state.writing = true;
  state.sync = true;
  if (state.destroyed) state.onwrite(new ERR_STREAM_DESTROYED('write'));else if (writev) stream._writev(chunk, state.onwrite);else stream._write(chunk, encoding, state.onwrite);
  state.sync = false;
}

function onwriteError(stream, state, sync, er, cb) {
  --state.pendingcb;

  if (sync) {
    // defer the callback if we are being called synchronously
    // to avoid piling up things on the stack
    process.nextTick(cb, er); // this can emit finish, and it will always happen
    // after error

    process.nextTick(finishMaybe, stream, state);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er);
  } else {
    // the caller expect this to happen before if
    // it is async
    cb(er);
    stream._writableState.errorEmitted = true;
    errorOrDestroy(stream, er); // this can emit finish, but finish must
    // always follow error

    finishMaybe(stream, state);
  }
}

function onwriteStateUpdate(state) {
  state.writing = false;
  state.writecb = null;
  state.length -= state.writelen;
  state.writelen = 0;
}

function onwrite(stream, er) {
  var state = stream._writableState;
  var sync = state.sync;
  var cb = state.writecb;
  if (typeof cb !== 'function') throw new ERR_MULTIPLE_CALLBACK();
  onwriteStateUpdate(state);
  if (er) onwriteError(stream, state, sync, er, cb);else {
    // Check if we're actually ready to finish, but don't emit yet
    var finished = needFinish(state) || stream.destroyed;

    if (!finished && !state.corked && !state.bufferProcessing && state.bufferedRequest) {
      clearBuffer(stream, state);
    }

    if (sync) {
      process.nextTick(afterWrite, stream, state, finished, cb);
    } else {
      afterWrite(stream, state, finished, cb);
    }
  }
}

function afterWrite(stream, state, finished, cb) {
  if (!finished) onwriteDrain(stream, state);
  state.pendingcb--;
  cb();
  finishMaybe(stream, state);
} // Must force callback to be called on nextTick, so that we don't
// emit 'drain' before the write() consumer gets the 'false' return
// value, and has a chance to attach a 'drain' listener.


function onwriteDrain(stream, state) {
  if (state.length === 0 && state.needDrain) {
    state.needDrain = false;
    stream.emit('drain');
  }
} // if there's something in the buffer waiting, then process it


function clearBuffer(stream, state) {
  state.bufferProcessing = true;
  var entry = state.bufferedRequest;

  if (stream._writev && entry && entry.next) {
    // Fast case, write everything using _writev()
    var l = state.bufferedRequestCount;
    var buffer = new Array(l);
    var holder = state.corkedRequestsFree;
    holder.entry = entry;
    var count = 0;
    var allBuffers = true;

    while (entry) {
      buffer[count] = entry;
      if (!entry.isBuf) allBuffers = false;
      entry = entry.next;
      count += 1;
    }

    buffer.allBuffers = allBuffers;
    doWrite(stream, state, true, state.length, buffer, '', holder.finish); // doWrite is almost always async, defer these to save a bit of time
    // as the hot path ends with doWrite

    state.pendingcb++;
    state.lastBufferedRequest = null;

    if (holder.next) {
      state.corkedRequestsFree = holder.next;
      holder.next = null;
    } else {
      state.corkedRequestsFree = new CorkedRequest(state);
    }

    state.bufferedRequestCount = 0;
  } else {
    // Slow case, write chunks one-by-one
    while (entry) {
      var chunk = entry.chunk;
      var encoding = entry.encoding;
      var cb = entry.callback;
      var len = state.objectMode ? 1 : chunk.length;
      doWrite(stream, state, false, len, chunk, encoding, cb);
      entry = entry.next;
      state.bufferedRequestCount--; // if we didn't call the onwrite immediately, then
      // it means that we need to wait until it does.
      // also, that means that the chunk and cb are currently
      // being processed, so move the buffer counter past them.

      if (state.writing) {
        break;
      }
    }

    if (entry === null) state.lastBufferedRequest = null;
  }

  state.bufferedRequest = entry;
  state.bufferProcessing = false;
}

Writable.prototype._write = function (chunk, encoding, cb) {
  cb(new ERR_METHOD_NOT_IMPLEMENTED('_write()'));
};

Writable.prototype._writev = null;

Writable.prototype.end = function (chunk, encoding, cb) {
  var state = this._writableState;

  if (typeof chunk === 'function') {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === 'function') {
    cb = encoding;
    encoding = null;
  }

  if (chunk !== null && chunk !== undefined) this.write(chunk, encoding); // .end() fully uncorks

  if (state.corked) {
    state.corked = 1;
    this.uncork();
  } // ignore unnecessary end() calls.


  if (!state.ending) endWritable(this, state, cb);
  return this;
};

Object.defineProperty(Writable.prototype, 'writableLength', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    return this._writableState.length;
  }
});

function needFinish(state) {
  return state.ending && state.length === 0 && state.bufferedRequest === null && !state.finished && !state.writing;
}

function callFinal(stream, state) {
  stream._final(function (err) {
    state.pendingcb--;

    if (err) {
      errorOrDestroy(stream, err);
    }

    state.prefinished = true;
    stream.emit('prefinish');
    finishMaybe(stream, state);
  });
}

function prefinish(stream, state) {
  if (!state.prefinished && !state.finalCalled) {
    if (typeof stream._final === 'function' && !state.destroyed) {
      state.pendingcb++;
      state.finalCalled = true;
      process.nextTick(callFinal, stream, state);
    } else {
      state.prefinished = true;
      stream.emit('prefinish');
    }
  }
}

function finishMaybe(stream, state) {
  var need = needFinish(state);

  if (need) {
    prefinish(stream, state);

    if (state.pendingcb === 0) {
      state.finished = true;
      stream.emit('finish');

      if (state.autoDestroy) {
        // In case of duplex streams we need a way to detect
        // if the readable side is ready for autoDestroy as well
        var rState = stream._readableState;

        if (!rState || rState.autoDestroy && rState.endEmitted) {
          stream.destroy();
        }
      }
    }
  }

  return need;
}

function endWritable(stream, state, cb) {
  state.ending = true;
  finishMaybe(stream, state);

  if (cb) {
    if (state.finished) process.nextTick(cb);else stream.once('finish', cb);
  }

  state.ended = true;
  stream.writable = false;
}

function onCorkedFinish(corkReq, state, err) {
  var entry = corkReq.entry;
  corkReq.entry = null;

  while (entry) {
    var cb = entry.callback;
    state.pendingcb--;
    cb(err);
    entry = entry.next;
  } // reuse the free corkReq.


  state.corkedRequestsFree.next = corkReq;
}

Object.defineProperty(Writable.prototype, 'destroyed', {
  // making it explicit this property is not enumerable
  // because otherwise some prototype manipulation in
  // userland will fail
  enumerable: false,
  get: function get() {
    if (this._writableState === undefined) {
      return false;
    }

    return this._writableState.destroyed;
  },
  set: function set(value) {
    // we ignore the value if the stream
    // has not been initialized yet
    if (!this._writableState) {
      return;
    } // backward compatibility, the user is explicitly
    // managing destroyed


    this._writableState.destroyed = value;
  }
});
Writable.prototype.destroy = destroyImpl.destroy;
Writable.prototype._undestroy = destroyImpl.undestroy;

Writable.prototype._destroy = function (err, cb) {
  cb(err);
};
}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../errors":67,"./_stream_duplex":68,"./internal/streams/destroy":75,"./internal/streams/state":79,"./internal/streams/stream":80,"_process":66,"buffer":62,"inherits":65,"util-deprecate":95}],73:[function(require,module,exports){
(function (process){
'use strict';

var _Object$setPrototypeO;

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var finished = require('./end-of-stream');

var kLastResolve = Symbol('lastResolve');
var kLastReject = Symbol('lastReject');
var kError = Symbol('error');
var kEnded = Symbol('ended');
var kLastPromise = Symbol('lastPromise');
var kHandlePromise = Symbol('handlePromise');
var kStream = Symbol('stream');

function createIterResult(value, done) {
  return {
    value: value,
    done: done
  };
}

function readAndResolve(iter) {
  var resolve = iter[kLastResolve];

  if (resolve !== null) {
    var data = iter[kStream].read(); // we defer if data is null
    // we can be expecting either 'end' or
    // 'error'

    if (data !== null) {
      iter[kLastPromise] = null;
      iter[kLastResolve] = null;
      iter[kLastReject] = null;
      resolve(createIterResult(data, false));
    }
  }
}

function onReadable(iter) {
  // we wait for the next tick, because it might
  // emit an error with process.nextTick
  process.nextTick(readAndResolve, iter);
}

function wrapForNext(lastPromise, iter) {
  return function (resolve, reject) {
    lastPromise.then(function () {
      if (iter[kEnded]) {
        resolve(createIterResult(undefined, true));
        return;
      }

      iter[kHandlePromise](resolve, reject);
    }, reject);
  };
}

var AsyncIteratorPrototype = Object.getPrototypeOf(function () {});
var ReadableStreamAsyncIteratorPrototype = Object.setPrototypeOf((_Object$setPrototypeO = {
  get stream() {
    return this[kStream];
  },

  next: function next() {
    var _this = this;

    // if we have detected an error in the meanwhile
    // reject straight away
    var error = this[kError];

    if (error !== null) {
      return Promise.reject(error);
    }

    if (this[kEnded]) {
      return Promise.resolve(createIterResult(undefined, true));
    }

    if (this[kStream].destroyed) {
      // We need to defer via nextTick because if .destroy(err) is
      // called, the error will be emitted via nextTick, and
      // we cannot guarantee that there is no error lingering around
      // waiting to be emitted.
      return new Promise(function (resolve, reject) {
        process.nextTick(function () {
          if (_this[kError]) {
            reject(_this[kError]);
          } else {
            resolve(createIterResult(undefined, true));
          }
        });
      });
    } // if we have multiple next() calls
    // we will wait for the previous Promise to finish
    // this logic is optimized to support for await loops,
    // where next() is only called once at a time


    var lastPromise = this[kLastPromise];
    var promise;

    if (lastPromise) {
      promise = new Promise(wrapForNext(lastPromise, this));
    } else {
      // fast path needed to support multiple this.push()
      // without triggering the next() queue
      var data = this[kStream].read();

      if (data !== null) {
        return Promise.resolve(createIterResult(data, false));
      }

      promise = new Promise(this[kHandlePromise]);
    }

    this[kLastPromise] = promise;
    return promise;
  }
}, _defineProperty(_Object$setPrototypeO, Symbol.asyncIterator, function () {
  return this;
}), _defineProperty(_Object$setPrototypeO, "return", function _return() {
  var _this2 = this;

  // destroy(err, cb) is a private API
  // we can guarantee we have that here, because we control the
  // Readable class this is attached to
  return new Promise(function (resolve, reject) {
    _this2[kStream].destroy(null, function (err) {
      if (err) {
        reject(err);
        return;
      }

      resolve(createIterResult(undefined, true));
    });
  });
}), _Object$setPrototypeO), AsyncIteratorPrototype);

var createReadableStreamAsyncIterator = function createReadableStreamAsyncIterator(stream) {
  var _Object$create;

  var iterator = Object.create(ReadableStreamAsyncIteratorPrototype, (_Object$create = {}, _defineProperty(_Object$create, kStream, {
    value: stream,
    writable: true
  }), _defineProperty(_Object$create, kLastResolve, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kLastReject, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kError, {
    value: null,
    writable: true
  }), _defineProperty(_Object$create, kEnded, {
    value: stream._readableState.endEmitted,
    writable: true
  }), _defineProperty(_Object$create, kHandlePromise, {
    value: function value(resolve, reject) {
      var data = iterator[kStream].read();

      if (data) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        resolve(createIterResult(data, false));
      } else {
        iterator[kLastResolve] = resolve;
        iterator[kLastReject] = reject;
      }
    },
    writable: true
  }), _Object$create));
  iterator[kLastPromise] = null;
  finished(stream, function (err) {
    if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
      var reject = iterator[kLastReject]; // reject if we are waiting for data in the Promise
      // returned by next() and store the error

      if (reject !== null) {
        iterator[kLastPromise] = null;
        iterator[kLastResolve] = null;
        iterator[kLastReject] = null;
        reject(err);
      }

      iterator[kError] = err;
      return;
    }

    var resolve = iterator[kLastResolve];

    if (resolve !== null) {
      iterator[kLastPromise] = null;
      iterator[kLastResolve] = null;
      iterator[kLastReject] = null;
      resolve(createIterResult(undefined, true));
    }

    iterator[kEnded] = true;
  });
  stream.on('readable', onReadable.bind(null, iterator));
  return iterator;
};

module.exports = createReadableStreamAsyncIterator;
}).call(this,require('_process'))
},{"./end-of-stream":76,"_process":66}],74:[function(require,module,exports){
'use strict';

function ownKeys(object, enumerableOnly) { var keys = Object.keys(object); if (Object.getOwnPropertySymbols) { var symbols = Object.getOwnPropertySymbols(object); if (enumerableOnly) symbols = symbols.filter(function (sym) { return Object.getOwnPropertyDescriptor(object, sym).enumerable; }); keys.push.apply(keys, symbols); } return keys; }

function _objectSpread(target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i] != null ? arguments[i] : {}; if (i % 2) { ownKeys(Object(source), true).forEach(function (key) { _defineProperty(target, key, source[key]); }); } else if (Object.getOwnPropertyDescriptors) { Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)); } else { ownKeys(Object(source)).forEach(function (key) { Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key)); }); } } return target; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

var _require = require('buffer'),
    Buffer = _require.Buffer;

var _require2 = require('util'),
    inspect = _require2.inspect;

var custom = inspect && inspect.custom || 'inspect';

function copyBuffer(src, target, offset) {
  Buffer.prototype.copy.call(src, target, offset);
}

module.exports =
/*#__PURE__*/
function () {
  function BufferList() {
    _classCallCheck(this, BufferList);

    this.head = null;
    this.tail = null;
    this.length = 0;
  }

  _createClass(BufferList, [{
    key: "push",
    value: function push(v) {
      var entry = {
        data: v,
        next: null
      };
      if (this.length > 0) this.tail.next = entry;else this.head = entry;
      this.tail = entry;
      ++this.length;
    }
  }, {
    key: "unshift",
    value: function unshift(v) {
      var entry = {
        data: v,
        next: this.head
      };
      if (this.length === 0) this.tail = entry;
      this.head = entry;
      ++this.length;
    }
  }, {
    key: "shift",
    value: function shift() {
      if (this.length === 0) return;
      var ret = this.head.data;
      if (this.length === 1) this.head = this.tail = null;else this.head = this.head.next;
      --this.length;
      return ret;
    }
  }, {
    key: "clear",
    value: function clear() {
      this.head = this.tail = null;
      this.length = 0;
    }
  }, {
    key: "join",
    value: function join(s) {
      if (this.length === 0) return '';
      var p = this.head;
      var ret = '' + p.data;

      while (p = p.next) {
        ret += s + p.data;
      }

      return ret;
    }
  }, {
    key: "concat",
    value: function concat(n) {
      if (this.length === 0) return Buffer.alloc(0);
      var ret = Buffer.allocUnsafe(n >>> 0);
      var p = this.head;
      var i = 0;

      while (p) {
        copyBuffer(p.data, ret, i);
        i += p.data.length;
        p = p.next;
      }

      return ret;
    } // Consumes a specified amount of bytes or characters from the buffered data.

  }, {
    key: "consume",
    value: function consume(n, hasStrings) {
      var ret;

      if (n < this.head.data.length) {
        // `slice` is the same for buffers and strings.
        ret = this.head.data.slice(0, n);
        this.head.data = this.head.data.slice(n);
      } else if (n === this.head.data.length) {
        // First chunk is a perfect match.
        ret = this.shift();
      } else {
        // Result spans more than one buffer.
        ret = hasStrings ? this._getString(n) : this._getBuffer(n);
      }

      return ret;
    }
  }, {
    key: "first",
    value: function first() {
      return this.head.data;
    } // Consumes a specified amount of characters from the buffered data.

  }, {
    key: "_getString",
    value: function _getString(n) {
      var p = this.head;
      var c = 1;
      var ret = p.data;
      n -= ret.length;

      while (p = p.next) {
        var str = p.data;
        var nb = n > str.length ? str.length : n;
        if (nb === str.length) ret += str;else ret += str.slice(0, n);
        n -= nb;

        if (n === 0) {
          if (nb === str.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = str.slice(nb);
          }

          break;
        }

        ++c;
      }

      this.length -= c;
      return ret;
    } // Consumes a specified amount of bytes from the buffered data.

  }, {
    key: "_getBuffer",
    value: function _getBuffer(n) {
      var ret = Buffer.allocUnsafe(n);
      var p = this.head;
      var c = 1;
      p.data.copy(ret);
      n -= p.data.length;

      while (p = p.next) {
        var buf = p.data;
        var nb = n > buf.length ? buf.length : n;
        buf.copy(ret, ret.length - n, 0, nb);
        n -= nb;

        if (n === 0) {
          if (nb === buf.length) {
            ++c;
            if (p.next) this.head = p.next;else this.head = this.tail = null;
          } else {
            this.head = p;
            p.data = buf.slice(nb);
          }

          break;
        }

        ++c;
      }

      this.length -= c;
      return ret;
    } // Make sure the linked list only shows the minimal necessary information.

  }, {
    key: custom,
    value: function value(_, options) {
      return inspect(this, _objectSpread({}, options, {
        // Only inspect one level.
        depth: 0,
        // It should not recurse.
        customInspect: false
      }));
    }
  }]);

  return BufferList;
}();
},{"buffer":62,"util":60}],75:[function(require,module,exports){
(function (process){
'use strict'; // undocumented cb() API, needed for core, not for public API

function destroy(err, cb) {
  var _this = this;

  var readableDestroyed = this._readableState && this._readableState.destroyed;
  var writableDestroyed = this._writableState && this._writableState.destroyed;

  if (readableDestroyed || writableDestroyed) {
    if (cb) {
      cb(err);
    } else if (err) {
      if (!this._writableState) {
        process.nextTick(emitErrorNT, this, err);
      } else if (!this._writableState.errorEmitted) {
        this._writableState.errorEmitted = true;
        process.nextTick(emitErrorNT, this, err);
      }
    }

    return this;
  } // we set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case destroy() is called within callbacks


  if (this._readableState) {
    this._readableState.destroyed = true;
  } // if this is a duplex stream mark the writable part as destroyed as well


  if (this._writableState) {
    this._writableState.destroyed = true;
  }

  this._destroy(err || null, function (err) {
    if (!cb && err) {
      if (!_this._writableState) {
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else if (!_this._writableState.errorEmitted) {
        _this._writableState.errorEmitted = true;
        process.nextTick(emitErrorAndCloseNT, _this, err);
      } else {
        process.nextTick(emitCloseNT, _this);
      }
    } else if (cb) {
      process.nextTick(emitCloseNT, _this);
      cb(err);
    } else {
      process.nextTick(emitCloseNT, _this);
    }
  });

  return this;
}

function emitErrorAndCloseNT(self, err) {
  emitErrorNT(self, err);
  emitCloseNT(self);
}

function emitCloseNT(self) {
  if (self._writableState && !self._writableState.emitClose) return;
  if (self._readableState && !self._readableState.emitClose) return;
  self.emit('close');
}

function undestroy() {
  if (this._readableState) {
    this._readableState.destroyed = false;
    this._readableState.reading = false;
    this._readableState.ended = false;
    this._readableState.endEmitted = false;
  }

  if (this._writableState) {
    this._writableState.destroyed = false;
    this._writableState.ended = false;
    this._writableState.ending = false;
    this._writableState.finalCalled = false;
    this._writableState.prefinished = false;
    this._writableState.finished = false;
    this._writableState.errorEmitted = false;
  }
}

function emitErrorNT(self, err) {
  self.emit('error', err);
}

function errorOrDestroy(stream, err) {
  // We have tests that rely on errors being emitted
  // in the same tick, so changing this is semver major.
  // For now when you opt-in to autoDestroy we allow
  // the error to be emitted nextTick. In a future
  // semver major update we should change the default to this.
  var rState = stream._readableState;
  var wState = stream._writableState;
  if (rState && rState.autoDestroy || wState && wState.autoDestroy) stream.destroy(err);else stream.emit('error', err);
}

module.exports = {
  destroy: destroy,
  undestroy: undestroy,
  errorOrDestroy: errorOrDestroy
};
}).call(this,require('_process'))
},{"_process":66}],76:[function(require,module,exports){
// Ported from https://github.com/mafintosh/end-of-stream with
// permission from the author, Mathias Buus (@mafintosh).
'use strict';

var ERR_STREAM_PREMATURE_CLOSE = require('../../../errors').codes.ERR_STREAM_PREMATURE_CLOSE;

function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;

    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    callback.apply(this, args);
  };
}

function noop() {}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}

function eos(stream, opts, callback) {
  if (typeof opts === 'function') return eos(stream, null, opts);
  if (!opts) opts = {};
  callback = once(callback || noop);
  var readable = opts.readable || opts.readable !== false && stream.readable;
  var writable = opts.writable || opts.writable !== false && stream.writable;

  var onlegacyfinish = function onlegacyfinish() {
    if (!stream.writable) onfinish();
  };

  var writableEnded = stream._writableState && stream._writableState.finished;

  var onfinish = function onfinish() {
    writable = false;
    writableEnded = true;
    if (!readable) callback.call(stream);
  };

  var readableEnded = stream._readableState && stream._readableState.endEmitted;

  var onend = function onend() {
    readable = false;
    readableEnded = true;
    if (!writable) callback.call(stream);
  };

  var onerror = function onerror(err) {
    callback.call(stream, err);
  };

  var onclose = function onclose() {
    var err;

    if (readable && !readableEnded) {
      if (!stream._readableState || !stream._readableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }

    if (writable && !writableEnded) {
      if (!stream._writableState || !stream._writableState.ended) err = new ERR_STREAM_PREMATURE_CLOSE();
      return callback.call(stream, err);
    }
  };

  var onrequest = function onrequest() {
    stream.req.on('finish', onfinish);
  };

  if (isRequest(stream)) {
    stream.on('complete', onfinish);
    stream.on('abort', onclose);
    if (stream.req) onrequest();else stream.on('request', onrequest);
  } else if (writable && !stream._writableState) {
    // legacy streams
    stream.on('end', onlegacyfinish);
    stream.on('close', onlegacyfinish);
  }

  stream.on('end', onend);
  stream.on('finish', onfinish);
  if (opts.error !== false) stream.on('error', onerror);
  stream.on('close', onclose);
  return function () {
    stream.removeListener('complete', onfinish);
    stream.removeListener('abort', onclose);
    stream.removeListener('request', onrequest);
    if (stream.req) stream.req.removeListener('finish', onfinish);
    stream.removeListener('end', onlegacyfinish);
    stream.removeListener('close', onlegacyfinish);
    stream.removeListener('finish', onfinish);
    stream.removeListener('end', onend);
    stream.removeListener('error', onerror);
    stream.removeListener('close', onclose);
  };
}

module.exports = eos;
},{"../../../errors":67}],77:[function(require,module,exports){
module.exports = function () {
  throw new Error('Readable.from is not available in the browser')
};

},{}],78:[function(require,module,exports){
// Ported from https://github.com/mafintosh/pump with
// permission from the author, Mathias Buus (@mafintosh).
'use strict';

var eos;

function once(callback) {
  var called = false;
  return function () {
    if (called) return;
    called = true;
    callback.apply(void 0, arguments);
  };
}

var _require$codes = require('../../../errors').codes,
    ERR_MISSING_ARGS = _require$codes.ERR_MISSING_ARGS,
    ERR_STREAM_DESTROYED = _require$codes.ERR_STREAM_DESTROYED;

function noop(err) {
  // Rethrow the error if it exists to avoid swallowing it
  if (err) throw err;
}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === 'function';
}

function destroyer(stream, reading, writing, callback) {
  callback = once(callback);
  var closed = false;
  stream.on('close', function () {
    closed = true;
  });
  if (eos === undefined) eos = require('./end-of-stream');
  eos(stream, {
    readable: reading,
    writable: writing
  }, function (err) {
    if (err) return callback(err);
    closed = true;
    callback();
  });
  var destroyed = false;
  return function (err) {
    if (closed) return;
    if (destroyed) return;
    destroyed = true; // request.destroy just do .end - .abort is what we want

    if (isRequest(stream)) return stream.abort();
    if (typeof stream.destroy === 'function') return stream.destroy();
    callback(err || new ERR_STREAM_DESTROYED('pipe'));
  };
}

function call(fn) {
  fn();
}

function pipe(from, to) {
  return from.pipe(to);
}

function popCallback(streams) {
  if (!streams.length) return noop;
  if (typeof streams[streams.length - 1] !== 'function') return noop;
  return streams.pop();
}

function pipeline() {
  for (var _len = arguments.length, streams = new Array(_len), _key = 0; _key < _len; _key++) {
    streams[_key] = arguments[_key];
  }

  var callback = popCallback(streams);
  if (Array.isArray(streams[0])) streams = streams[0];

  if (streams.length < 2) {
    throw new ERR_MISSING_ARGS('streams');
  }

  var error;
  var destroys = streams.map(function (stream, i) {
    var reading = i < streams.length - 1;
    var writing = i > 0;
    return destroyer(stream, reading, writing, function (err) {
      if (!error) error = err;
      if (err) destroys.forEach(call);
      if (reading) return;
      destroys.forEach(call);
      callback(error);
    });
  });
  return streams.reduce(pipe);
}

module.exports = pipeline;
},{"../../../errors":67,"./end-of-stream":76}],79:[function(require,module,exports){
'use strict';

var ERR_INVALID_OPT_VALUE = require('../../../errors').codes.ERR_INVALID_OPT_VALUE;

function highWaterMarkFrom(options, isDuplex, duplexKey) {
  return options.highWaterMark != null ? options.highWaterMark : isDuplex ? options[duplexKey] : null;
}

function getHighWaterMark(state, options, duplexKey, isDuplex) {
  var hwm = highWaterMarkFrom(options, isDuplex, duplexKey);

  if (hwm != null) {
    if (!(isFinite(hwm) && Math.floor(hwm) === hwm) || hwm < 0) {
      var name = isDuplex ? duplexKey : 'highWaterMark';
      throw new ERR_INVALID_OPT_VALUE(name, hwm);
    }

    return Math.floor(hwm);
  } // Default value


  return state.objectMode ? 16 : 16 * 1024;
}

module.exports = {
  getHighWaterMark: getHighWaterMark
};
},{"../../../errors":67}],80:[function(require,module,exports){
module.exports = require('events').EventEmitter;

},{"events":63}],81:[function(require,module,exports){
exports = module.exports = require('./lib/_stream_readable.js');
exports.Stream = exports;
exports.Readable = exports;
exports.Writable = require('./lib/_stream_writable.js');
exports.Duplex = require('./lib/_stream_duplex.js');
exports.Transform = require('./lib/_stream_transform.js');
exports.PassThrough = require('./lib/_stream_passthrough.js');
exports.finished = require('./lib/internal/streams/end-of-stream.js');
exports.pipeline = require('./lib/internal/streams/pipeline.js');

},{"./lib/_stream_duplex.js":68,"./lib/_stream_passthrough.js":69,"./lib/_stream_readable.js":70,"./lib/_stream_transform.js":71,"./lib/_stream_writable.js":72,"./lib/internal/streams/end-of-stream.js":76,"./lib/internal/streams/pipeline.js":78}],82:[function(require,module,exports){
/*! safe-buffer. MIT License. Feross Aboukhadijeh <https://feross.org/opensource> */
/* eslint-disable node/no-deprecated-api */
var buffer = require('buffer')
var Buffer = buffer.Buffer

// alternative to using Object.keys for old browsers
function copyProps (src, dst) {
  for (var key in src) {
    dst[key] = src[key]
  }
}
if (Buffer.from && Buffer.alloc && Buffer.allocUnsafe && Buffer.allocUnsafeSlow) {
  module.exports = buffer
} else {
  // Copy properties from require('buffer')
  copyProps(buffer, exports)
  exports.Buffer = SafeBuffer
}

function SafeBuffer (arg, encodingOrOffset, length) {
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.prototype = Object.create(Buffer.prototype)

// Copy static methods from Buffer
copyProps(Buffer, SafeBuffer)

SafeBuffer.from = function (arg, encodingOrOffset, length) {
  if (typeof arg === 'number') {
    throw new TypeError('Argument must not be a number')
  }
  return Buffer(arg, encodingOrOffset, length)
}

SafeBuffer.alloc = function (size, fill, encoding) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  var buf = Buffer(size)
  if (fill !== undefined) {
    if (typeof encoding === 'string') {
      buf.fill(fill, encoding)
    } else {
      buf.fill(fill)
    }
  } else {
    buf.fill(0)
  }
  return buf
}

SafeBuffer.allocUnsafe = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return Buffer(size)
}

SafeBuffer.allocUnsafeSlow = function (size) {
  if (typeof size !== 'number') {
    throw new TypeError('Argument must be a number')
  }
  return buffer.SlowBuffer(size)
}

},{"buffer":62}],83:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=exports.SHAKE=exports.SHA3Hash=exports.SHA3=exports.Keccak=void 0;var _buffer=require("buffer");var _sponge=_interopRequireDefault(require("./sponge"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var createHash=function createHash(_ref){var allowedSizes=_ref.allowedSizes,padding=_ref.padding;return function Hash(){var _this=this;var size=arguments.length>0&&arguments[0]!==undefined?arguments[0]:512;if(!this||this.constructor!==Hash){return new Hash(size)}if(allowedSizes&&!allowedSizes.includes(size)){throw new Error("Unsupported hash length")}var sponge=new _sponge["default"]({capacity:size});this.update=function(input){var encoding=arguments.length>1&&arguments[1]!==undefined?arguments[1]:"utf8";if(_buffer.Buffer.isBuffer(input)){sponge.absorb(input);return _this}if(typeof input==="string"){return _this.update(_buffer.Buffer.from(input,encoding))}throw new TypeError("Not a string or buffer")};this.digest=function(){var formatOrOptions=arguments.length>0&&arguments[0]!==undefined?arguments[0]:"binary";var options=typeof formatOrOptions==="string"?{format:formatOrOptions}:formatOrOptions;var buffer=sponge.squeeze({buffer:options.buffer,padding:options.padding||padding});if(options.format&&options.format!=="binary"){return buffer.toString(options.format)}return buffer};this.reset=function(){sponge.reset();return _this};return this}};var Keccak=createHash({allowedSizes:[224,256,384,512],padding:1});exports.Keccak=Keccak;var SHA3=createHash({allowedSizes:[224,256,384,512],padding:6});exports.SHA3=SHA3;var SHAKE=createHash({allowedSizes:[128,256],padding:31});exports.SHAKE=SHAKE;var SHA3Hash=Keccak;exports.SHA3Hash=SHA3Hash;SHA3.SHA3Hash=SHA3Hash;var _default=SHA3;exports["default"]=_default;
},{"./sponge":84,"buffer":62}],84:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var _buffer=require("buffer");var _permute=_interopRequireDefault(require("./permute"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var xorWords=function xorWords(I,O){for(var i=0;i<I.length;i+=8){var o=i/4;O[o]^=I[i+7]<<24|I[i+6]<<16|I[i+5]<<8|I[i+4];O[o+1]^=I[i+3]<<24|I[i+2]<<16|I[i+1]<<8|I[i]}return O};var readWords=function readWords(I,O){for(var o=0;o<O.length;o+=8){var i=o/4;O[o]=I[i+1];O[o+1]=I[i+1]>>>8;O[o+2]=I[i+1]>>>16;O[o+3]=I[i+1]>>>24;O[o+4]=I[i];O[o+5]=I[i]>>>8;O[o+6]=I[i]>>>16;O[o+7]=I[i]>>>24}return O};var Sponge=function Sponge(_ref){var _this=this;var capacity=_ref.capacity,padding=_ref.padding;var keccak=(0,_permute["default"])();var stateSize=200;var blockSize=capacity/8;var queueSize=stateSize-capacity/4;var queueOffset=0;var state=new Uint32Array(stateSize/4);var queue=_buffer.Buffer.allocUnsafe(queueSize);this.absorb=function(buffer){for(var i=0;i<buffer.length;i++){queue[queueOffset]=buffer[i];queueOffset+=1;if(queueOffset>=queueSize){xorWords(queue,state);keccak(state);queueOffset=0}}return _this};this.squeeze=function(){var options=arguments.length>0&&arguments[0]!==undefined?arguments[0]:{};var output={buffer:options.buffer||_buffer.Buffer.allocUnsafe(blockSize),padding:options.padding||padding,queue:_buffer.Buffer.allocUnsafe(queue.length),state:new Uint32Array(state.length)};queue.copy(output.queue);for(var i=0;i<state.length;i++){output.state[i]=state[i]}output.queue.fill(0,queueOffset);output.queue[queueOffset]|=output.padding;output.queue[queueSize-1]|=128;xorWords(output.queue,output.state);for(var offset=0;offset<output.buffer.length;offset+=queueSize){keccak(output.state);readWords(output.state,output.buffer.slice(offset,offset+queueSize))}return output.buffer};this.reset=function(){queue.fill(0);state.fill(0);queueOffset=0;return _this};return this};var _default=Sponge;exports["default"]=_default;
},{"./permute":87,"buffer":62}],85:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var _copy=_interopRequireDefault(require("../copy"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var chi=function chi(_ref){var A=_ref.A,C=_ref.C;for(var y=0;y<25;y+=5){for(var x=0;x<5;x++){(0,_copy["default"])(A,y+x)(C,x)}for(var _x=0;_x<5;_x++){var xy=(y+_x)*2;var x1=(_x+1)%5*2;var x2=(_x+2)%5*2;A[xy]^=~C[x1]&C[x2];A[xy+1]^=~C[x1+1]&C[x2+1]}}};var _default=chi;exports["default"]=_default;
},{"../copy":86}],86:[function(require,module,exports){
"use strict";var copy=function copy(I,i){return function(O,o){var oi=o*2;var ii=i*2;O[oi]=I[ii];O[oi+1]=I[ii+1]}};module.exports=copy;
},{}],87:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var _chi=_interopRequireDefault(require("./chi"));var _iota=_interopRequireDefault(require("./iota"));var _rhoPi=_interopRequireDefault(require("./rho-pi"));var _theta=_interopRequireDefault(require("./theta"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var permute=function permute(){var C=new Uint32Array(10);var D=new Uint32Array(10);var W=new Uint32Array(2);return function(A){for(var roundIndex=0;roundIndex<24;roundIndex++){(0,_theta["default"])({A:A,C:C,D:D,W:W});(0,_rhoPi["default"])({A:A,C:C,W:W});(0,_chi["default"])({A:A,C:C});(0,_iota["default"])({A:A,roundIndex:roundIndex})}C.fill(0);D.fill(0);W.fill(0)}};var _default=permute;exports["default"]=_default;
},{"./chi":85,"./iota":88,"./rho-pi":90,"./theta":93}],88:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var _roundConstants=_interopRequireDefault(require("./round-constants"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var iota=function iota(_ref){var A=_ref.A,roundIndex=_ref.roundIndex;var i=roundIndex*2;A[0]^=_roundConstants["default"][i];A[1]^=_roundConstants["default"][i+1]};var _default=iota;exports["default"]=_default;
},{"./round-constants":89}],89:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var ROUND_CONSTANTS=new Uint32Array([0,1,0,32898,2147483648,32906,2147483648,2147516416,0,32907,0,2147483649,2147483648,2147516545,2147483648,32777,0,138,0,136,0,2147516425,0,2147483658,0,2147516555,2147483648,139,2147483648,32905,2147483648,32771,2147483648,32770,2147483648,128,0,32778,2147483648,2147483658,2147483648,2147516545,2147483648,32896,0,2147483649,2147483648,2147516424]);var _default=ROUND_CONSTANTS;exports["default"]=_default;
},{}],90:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var _piShuffles=_interopRequireDefault(require("./pi-shuffles"));var _rhoOffsets=_interopRequireDefault(require("./rho-offsets"));var _copy=_interopRequireDefault(require("../copy"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var rhoPi=function rhoPi(_ref){var A=_ref.A,C=_ref.C,W=_ref.W;(0,_copy["default"])(A,1)(W,0);var H=0;var L=0;var Wi=0;var ri=32;for(var i=0;i<24;i++){var j=_piShuffles["default"][i];var r=_rhoOffsets["default"][i];(0,_copy["default"])(A,j)(C,0);H=W[0];L=W[1];ri=32-r;Wi=r<32?0:1;W[Wi]=H<<r|L>>>ri;W[(Wi+1)%2]=L<<r|H>>>ri;(0,_copy["default"])(W,0)(A,j);(0,_copy["default"])(C,0)(W,0)}};var _default=rhoPi;exports["default"]=_default;
},{"../copy":86,"./pi-shuffles":91,"./rho-offsets":92}],91:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var PI_SHUFFLES=[10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1];var _default=PI_SHUFFLES;exports["default"]=_default;
},{}],92:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var RHO_OFFSETS=[1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44];var _default=RHO_OFFSETS;exports["default"]=_default;
},{}],93:[function(require,module,exports){
"use strict";Object.defineProperty(exports,"__esModule",{value:true});exports["default"]=void 0;var _copy=_interopRequireDefault(require("../copy"));function _interopRequireDefault(obj){return obj&&obj.__esModule?obj:{"default":obj}}var theta=function theta(_ref){var A=_ref.A,C=_ref.C,D=_ref.D,W=_ref.W;var H=0;var L=0;for(var x=0;x<5;x++){var x20=x*2;var x21=(x+5)*2;var x22=(x+10)*2;var x23=(x+15)*2;var x24=(x+20)*2;C[x20]=A[x20]^A[x21]^A[x22]^A[x23]^A[x24];C[x20+1]=A[x20+1]^A[x21+1]^A[x22+1]^A[x23+1]^A[x24+1]}for(var _x=0;_x<5;_x++){(0,_copy["default"])(C,(_x+1)%5)(W,0);H=W[0];L=W[1];W[0]=H<<1|L>>>31;W[1]=L<<1|H>>>31;D[_x*2]=C[(_x+4)%5*2]^W[0];D[_x*2+1]=C[(_x+4)%5*2+1]^W[1];for(var y=0;y<25;y+=5){A[(y+_x)*2]^=D[_x*2];A[(y+_x)*2+1]^=D[_x*2+1]}}};var _default=theta;exports["default"]=_default;
},{"../copy":86}],94:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

/*<replacement>*/

var Buffer = require('safe-buffer').Buffer;
/*</replacement>*/

var isEncoding = Buffer.isEncoding || function (encoding) {
  encoding = '' + encoding;
  switch (encoding && encoding.toLowerCase()) {
    case 'hex':case 'utf8':case 'utf-8':case 'ascii':case 'binary':case 'base64':case 'ucs2':case 'ucs-2':case 'utf16le':case 'utf-16le':case 'raw':
      return true;
    default:
      return false;
  }
};

function _normalizeEncoding(enc) {
  if (!enc) return 'utf8';
  var retried;
  while (true) {
    switch (enc) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'base64':
      case 'ascii':
      case 'hex':
        return enc;
      default:
        if (retried) return; // undefined
        enc = ('' + enc).toLowerCase();
        retried = true;
    }
  }
};

// Do not cache `Buffer.isEncoding` when checking encoding names as some
// modules monkey-patch it to support additional encodings
function normalizeEncoding(enc) {
  var nenc = _normalizeEncoding(enc);
  if (typeof nenc !== 'string' && (Buffer.isEncoding === isEncoding || !isEncoding(enc))) throw new Error('Unknown encoding: ' + enc);
  return nenc || enc;
}

// StringDecoder provides an interface for efficiently splitting a series of
// buffers into a series of JS strings without breaking apart multi-byte
// characters.
exports.StringDecoder = StringDecoder;
function StringDecoder(encoding) {
  this.encoding = normalizeEncoding(encoding);
  var nb;
  switch (this.encoding) {
    case 'utf16le':
      this.text = utf16Text;
      this.end = utf16End;
      nb = 4;
      break;
    case 'utf8':
      this.fillLast = utf8FillLast;
      nb = 4;
      break;
    case 'base64':
      this.text = base64Text;
      this.end = base64End;
      nb = 3;
      break;
    default:
      this.write = simpleWrite;
      this.end = simpleEnd;
      return;
  }
  this.lastNeed = 0;
  this.lastTotal = 0;
  this.lastChar = Buffer.allocUnsafe(nb);
}

StringDecoder.prototype.write = function (buf) {
  if (buf.length === 0) return '';
  var r;
  var i;
  if (this.lastNeed) {
    r = this.fillLast(buf);
    if (r === undefined) return '';
    i = this.lastNeed;
    this.lastNeed = 0;
  } else {
    i = 0;
  }
  if (i < buf.length) return r ? r + this.text(buf, i) : this.text(buf, i);
  return r || '';
};

StringDecoder.prototype.end = utf8End;

// Returns only complete characters in a Buffer
StringDecoder.prototype.text = utf8Text;

// Attempts to complete a partial non-UTF-8 character using bytes from a Buffer
StringDecoder.prototype.fillLast = function (buf) {
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, buf.length);
  this.lastNeed -= buf.length;
};

// Checks the type of a UTF-8 byte, whether it's ASCII, a leading byte, or a
// continuation byte. If an invalid byte is detected, -2 is returned.
function utf8CheckByte(byte) {
  if (byte <= 0x7F) return 0;else if (byte >> 5 === 0x06) return 2;else if (byte >> 4 === 0x0E) return 3;else if (byte >> 3 === 0x1E) return 4;
  return byte >> 6 === 0x02 ? -1 : -2;
}

// Checks at most 3 bytes at the end of a Buffer in order to detect an
// incomplete multi-byte UTF-8 character. The total number of bytes (2, 3, or 4)
// needed to complete the UTF-8 character (if applicable) are returned.
function utf8CheckIncomplete(self, buf, i) {
  var j = buf.length - 1;
  if (j < i) return 0;
  var nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 1;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) self.lastNeed = nb - 2;
    return nb;
  }
  if (--j < i || nb === -2) return 0;
  nb = utf8CheckByte(buf[j]);
  if (nb >= 0) {
    if (nb > 0) {
      if (nb === 2) nb = 0;else self.lastNeed = nb - 3;
    }
    return nb;
  }
  return 0;
}

// Validates as many continuation bytes for a multi-byte UTF-8 character as
// needed or are available. If we see a non-continuation byte where we expect
// one, we "replace" the validated continuation bytes we've seen so far with
// a single UTF-8 replacement character ('\ufffd'), to match v8's UTF-8 decoding
// behavior. The continuation byte check is included three times in the case
// where all of the continuation bytes for a character exist in the same buffer.
// It is also done this way as a slight performance increase instead of using a
// loop.
function utf8CheckExtraBytes(self, buf, p) {
  if ((buf[0] & 0xC0) !== 0x80) {
    self.lastNeed = 0;
    return '\ufffd';
  }
  if (self.lastNeed > 1 && buf.length > 1) {
    if ((buf[1] & 0xC0) !== 0x80) {
      self.lastNeed = 1;
      return '\ufffd';
    }
    if (self.lastNeed > 2 && buf.length > 2) {
      if ((buf[2] & 0xC0) !== 0x80) {
        self.lastNeed = 2;
        return '\ufffd';
      }
    }
  }
}

// Attempts to complete a multi-byte UTF-8 character using bytes from a Buffer.
function utf8FillLast(buf) {
  var p = this.lastTotal - this.lastNeed;
  var r = utf8CheckExtraBytes(this, buf, p);
  if (r !== undefined) return r;
  if (this.lastNeed <= buf.length) {
    buf.copy(this.lastChar, p, 0, this.lastNeed);
    return this.lastChar.toString(this.encoding, 0, this.lastTotal);
  }
  buf.copy(this.lastChar, p, 0, buf.length);
  this.lastNeed -= buf.length;
}

// Returns all complete UTF-8 characters in a Buffer. If the Buffer ended on a
// partial character, the character's bytes are buffered until the required
// number of bytes are available.
function utf8Text(buf, i) {
  var total = utf8CheckIncomplete(this, buf, i);
  if (!this.lastNeed) return buf.toString('utf8', i);
  this.lastTotal = total;
  var end = buf.length - (total - this.lastNeed);
  buf.copy(this.lastChar, 0, end);
  return buf.toString('utf8', i, end);
}

// For UTF-8, a replacement character is added when ending on a partial
// character.
function utf8End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + '\ufffd';
  return r;
}

// UTF-16LE typically needs two bytes per character, but even if we have an even
// number of bytes available, we need to check if we end on a leading/high
// surrogate. In that case, we need to wait for the next two bytes in order to
// decode the last character properly.
function utf16Text(buf, i) {
  if ((buf.length - i) % 2 === 0) {
    var r = buf.toString('utf16le', i);
    if (r) {
      var c = r.charCodeAt(r.length - 1);
      if (c >= 0xD800 && c <= 0xDBFF) {
        this.lastNeed = 2;
        this.lastTotal = 4;
        this.lastChar[0] = buf[buf.length - 2];
        this.lastChar[1] = buf[buf.length - 1];
        return r.slice(0, -1);
      }
    }
    return r;
  }
  this.lastNeed = 1;
  this.lastTotal = 2;
  this.lastChar[0] = buf[buf.length - 1];
  return buf.toString('utf16le', i, buf.length - 1);
}

// For UTF-16LE we do not explicitly append special replacement characters if we
// end on a partial character, we simply let v8 handle that.
function utf16End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) {
    var end = this.lastTotal - this.lastNeed;
    return r + this.lastChar.toString('utf16le', 0, end);
  }
  return r;
}

function base64Text(buf, i) {
  var n = (buf.length - i) % 3;
  if (n === 0) return buf.toString('base64', i);
  this.lastNeed = 3 - n;
  this.lastTotal = 3;
  if (n === 1) {
    this.lastChar[0] = buf[buf.length - 1];
  } else {
    this.lastChar[0] = buf[buf.length - 2];
    this.lastChar[1] = buf[buf.length - 1];
  }
  return buf.toString('base64', i, buf.length - n);
}

function base64End(buf) {
  var r = buf && buf.length ? this.write(buf) : '';
  if (this.lastNeed) return r + this.lastChar.toString('base64', 0, 3 - this.lastNeed);
  return r;
}

// Pass bytes on through for single-byte encodings (e.g. ascii, latin1, hex)
function simpleWrite(buf) {
  return buf.toString(this.encoding);
}

function simpleEnd(buf) {
  return buf && buf.length ? this.write(buf) : '';
}
},{"safe-buffer":82}],95:[function(require,module,exports){
(function (global){

/**
 * Module exports.
 */

module.exports = deprecate;

/**
 * Mark that a method should not be used.
 * Returns a modified function which warns once by default.
 *
 * If `localStorage.noDeprecation = true` is set, then it is a no-op.
 *
 * If `localStorage.throwDeprecation = true` is set, then deprecated functions
 * will throw an Error when invoked.
 *
 * If `localStorage.traceDeprecation = true` is set, then deprecated functions
 * will invoke `console.trace()` instead of `console.error()`.
 *
 * @param {Function} fn - the function to deprecate
 * @param {String} msg - the string to print to the console when `fn` is invoked
 * @returns {Function} a new "deprecated" version of `fn`
 * @api public
 */

function deprecate (fn, msg) {
  if (config('noDeprecation')) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (config('throwDeprecation')) {
        throw new Error(msg);
      } else if (config('traceDeprecation')) {
        console.trace(msg);
      } else {
        console.warn(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
}

/**
 * Checks `localStorage` for boolean values for the given `name`.
 *
 * @param {String} name
 * @returns {Boolean}
 * @api private
 */

function config (name) {
  // accessing global.localStorage can trigger a DOMException in sandboxed iframes
  try {
    if (!global.localStorage) return false;
  } catch (_) {
    return false;
  }
  var val = global.localStorage[name];
  if (null == val) return false;
  return String(val).toLowerCase() === 'true';
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],96:[function(require,module,exports){
(function (Buffer){
const {Keccak} = require("sha3");
const {mainnet,testnet3} = require("@demos/chaincfg");
const {SignatureType} = require("@demos/dosec");
const {AddressPubKeyHash} = require("@demos/address");
const {FunctionParameter,ContractABI,ContractFunction} = require("@demos/contract");


module.exports = {
	async decode(abi, name, data, net = testnet3){
		if(!Array.isArray(abi)){
			throw new Error("abi is array");
		}
		if(!data){
			throw new Error("data is not null");
		}
		let ret = {};
		let params;
		for (let i = 0; i < abi.length; i++) {
			if(abi[i].type == "function" && abi[i].name == name){
				params = abi[i].inputs;
			}
		}
		if(!params){
			throw new Error("No matching function");
		}
		ret.name = name;
		if(!params.length){
			return ret;
		}

		ret.params = {};

		let parameters = [];

		for (let i = 0; i < params.length; i++) {
			parameters.push(new FunctionParameter(params[i].type, ContractABI.parseType(params[i].type)));
		}
		let func = new ContractFunction(name, parameters);
		let decoded = func.decode(data);
		for (let i = 0; i < decoded.length; i++) {
			if (params[i].type.match(/^uint/)) {
				ret.params[params[i].name] = decoded[i].toNumber();
				continue;
			}
			switch(params[i].type){
				case "address":
					let addr = new AddressPubKeyHash(decoded[i].toArrayLike(Buffer), net, SignatureType.STEcdsaSecp256k1);
					ret.params[params[i].name] = addr.encode();
					break;
				default:
					ret.params[params[i].name] = decoded[i];
					break;
			}
			
		}
		return ret;
	}
};

function sha3(data) {
	let hash = new Keccak(256);
	hash.update(data);
	return hash.digest();
}
}).call(this,require("buffer").Buffer)
},{"@demos/address":1,"@demos/chaincfg":3,"@demos/contract":6,"@demos/dosec":17,"buffer":62,"sha3":83}],97:[function(require,module,exports){
module.exports = {
    INVALID_NUMBER_OF_PARAMS: new Error('Invalid number of input parameters'),
    
    INVALID_PROVIDER: new Error('Provider not set or invalid'),
    INVALID_RESPONSE: (result) => {
        var message = !!result && !!result.error && !!result.error.message ? result.error.message : 'Invalid JSON RPC response: ' + JSON.stringify(result);
        return new Error(message);
    },
    CONNECTION_TIMEOUT: (ms) => {
    	return new Error('CONNECTION TIMEOUT: timeout of ' + ms + ' ms achived')
    },
    IS_NOT_A_FUNC: (name) => {
    	return new Error(`name is not a function`);
    }
}
},{}],98:[function(require,module,exports){

module.exports = {
	inputAddressFormatter(address){
		return address;
	},
	transferFormatter(data){
		return data.transactionHash || data;
	}
}
},{}],99:[function(require,module,exports){
(function (global){
const Method = require("./method");
const Interface = require("./interface");
const RpcEngine = require("./rpcengine");
const formatters = require("./formatters");
const transaction = require("./transaction");
const contract = require("./contract");

var methods = () => [
    new Method({
        name: 'getIdentity',
        call: 'identity',
        params: 0,
        desc: {
            help: "get current wallet address",
            params: "()",
            returns: {
                address: "wallet address"
            }
        }
    }),
    new Method({
        name: 'transfer',
        call: 'transfer',
        params: 2,
        inputFormatter: [formatters.inputAddressFormatter/*to*/, null/*amount*/],
        desc: {
            help: "current wallet transfer",
            params: "(string:to, double:amount)",
            returns: "txid"
        }
    }),
    new Method({
        name: 'btctransfer',
        call: 'btctransfer',
        params: 2,
        inputFormatter: [formatters.inputAddressFormatter/*to*/, null/*amount*/],
        outputFormatter: formatters.transferFormatter,
        desc: {
            help: "current btc wallet transfer",
            params: "(string:to, double:amount)",
            returns: "txid"
        }
    }),
    new Method({
        name: "contract",
        call: "contract",
        params: 3,
        inputFormatter: [null/*method*/, null/*contractAddress*/, null/*parameters*/],
        desc: {
            help: "current btc wallet transfer",
            params: "(string:to, double:amount)",
            returns: "txid"
        }
    }),
    new Method({
        name: "contractRaw",
        call: "contractRaw",
        params: 3,
        inputFormatter: [null/*method*/, null/*contractAddress*/, null/*parameters*/],
        desc: {
            help: "current btc wallet transfer",
            params: "(string:to, double:amount)",
            returns: "txid"
        }
    }),
    new Method({
        name: "share",
        call: "share",
        params: 1,
        inputFormatter: [null/*{ "id": 8, name: "2" }*/],
        desc: {
            help: "share dapp",
            params: "(object:{id: dappid})",
            returns: null
        }
    }),
    new Method({
        name: "shareImage",
        call: "shareImage",
        params: 1,
        inputFormatter: [null/*base64*/],
        desc: {
            help: "share image",
            params: "(string:\"base64\")",
            returns: null
        }
    }),
    new Method({
        name: "hideKeyboard",
        call: "hideKeyboard",
        params: 0,
        desc: {
            help: "hide keyboard",
            params: "()",
            returns: true
        }
    }),
    new Method({
        name: "showKeyboard",
        call: "showKeyboard",
        params: -1,
        desc: {
            help: "show keyboard",
            params: "([object:{value: \"input default value\",maxLength: 10/*输入框最大长度,不填则不限制*/,placeholder: \"placeholder\",multiple: false,//是否多行输入confirmText: \"完成\"/*不填写默认中文:完成, 英文done*/}])",
            returns: "input result"
        }
    }),
    new Method({
        name: "getClipboard",
        call: "getClipboard",
        params: 0,
        desc: {
            help: "get clipboard",
            params: "()",
            returns: "clipboard content"
        }
    }),
    new Method({
        name: "scanQRCode",
        call: "scanQRCode",
        params: 0,
        desc: {
            help: "scan qr code",
            params: "()",
            returns: "qrcode content"
        }
    }),
    new Method({
        name: "openFundManager",
        call: "openFundManager",
        params: 0,
        desc: {
            help: "open fund manager",
            params: "()",
            returns: null
        }
    }),
    new Method({
        name: "getVersion",
        call: "getVersion",
        params: 0,
        desc: {
            help: "getVersion",
            params: "()",
            returns: null
        }
    }),
    new Method({
        name: "canIUse",
        call: "canIUse",
        params: 1,
        desc: {
            help: "canIUse",
            params: "(method)",
            returns: 'true | false'
        }
    }),
    new Method({
        name: "request",
        call: "request",
        params: 1,
        desc: {
            help: "ajax request",
            params: "(options)",
            returns: '{url: "", method: "POST"|"GET", data: {"post 参数"}}'
        }
    }),
    new Method({
        name: "summary",
        call: "summary",
        params: 1,
        desc: {
            help: "dos wallet summary",
            params: "(Array<Map<String,String>>:utxos)",
            returns: '[{utxo content}]'
        }
    }),
    new Method({
        name: "exchange.info",
        call: "exchange_info",
        params: 1,
        desc: {
            help: "get exchange info",
            params: "(string:address)",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.order",
        call: "exchange_order",
        params: 3,
        desc: {
            help: "get exchange order",
            params: "(string:address, int:page, int:pageSize)",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.gains",
        call: "exchange_gains",
        params: 3,
        desc: {
            help: "get exchange gains",
            params: "(string:address, int:page, int:pageSize)",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.submit",
        call: "exchange_submit",
        params: 4,
        desc: {
            help: "exchange submit",
            params: "(string:address,string:invite,string:contract,double:amount)",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.repent",
        call: "exchange_repent",
        params: 3,
        desc: {
            help: "exchange repent",
            params: "(string:address, int:id, string:rawtx)",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.pmr",
        call: "exchange_pmr",
        params: 0,
        desc: {
            help: "get exchange pmr",
            params: "()",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.funds",
        call: "exchange_funds",
        params: 0,
        desc: {
            help: "get exchange funds",
            params: "()",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "exchange.state",
        call: "exchange_state",
        params: 0,
        desc: {
            help: "get exchange state",
            params: "()",
            returns: 'Map<String,dynamic>{}'
        }
    }),
    new Method({
        name: "balance",
        call: "balance",
        params: 1,
        desc: {
            help: "get balance",
            params: "([token])",
            returns: 'Number',
        }
    }),
    new Method({
        name: "token",
        call: "token",
        params: 1,
        desc: {
            help: "get token info",
            params: "(token)",
            returns: "object",
        }
    }),

    // TODO 
    // dosdata.chain
    //             .block(hash)
    //             .rawtransaction(hash)
    // dosdata.expand
    //             .block(hash)
    //             .rawtransaction(hash)
    //             .logs(contract)

    // dosdata.address
    //             .info(address)
    //             .balance(address),
    //             .token(address,contract)

    new Method({
        name: 'dosdata.chain.block',
        call: 'explorer',
        params: (args) => ['insight', `block/${args[0]}`],
        desc: {
            help: 'block',
            params: "(hash)",
            returns: "object",
        }
    }),
    new Method({
        name: 'dosdata.chain.transaction',
        call: 'explorer',
        params: (args) => ['insight', `tx/${args[0]}`],
        desc: {
            help: 'transaction',
            params: "(hash)",
            returns: "object",
        }
    }),
    new Method({
        name: 'dosdata.expand.block',
        call: 'explorer',
        params: (args) => ['insight', `sblock/${args[0]}`],
        desc: {
            help: 'block',
            params: "(hash)",
            returns: "object",
        }
    }),
    new Method({
        name: 'dosdata.expand.transaction',
        call: 'explorer',
        params: (args) => ['insight', `sdtx/${args[0]}`],
        desc: {
            help: 'transaction',
            params: "(hash)",
            returns: "object",
        }
    }),
    new Method({
        name: 'dosdata.expand.abi',
        call: 'explorer',
        params: (args) => ['insight', `contract/${args[0]}/abi`],
        desc: {
            help: "contract abi",
            params: "(contract)",
            returns: 'object',
        }
    }),
    new Method({
        name: "dosdata.expand.logs",
        call: "explorer",
        params: (args) => {
            let url = `contract/${args[0]}/logs`;
            if (args.length > 1) {
                url += `?`;
                for (var i in args[1]) {
                    url += `${i}=${args[1][i]}&`
                }
            }
            return ['insight', url]
        },
        desc: {
            help: "contract logs",
            params: "(contract,options)",
            return: 'object',
        }
    }),
    new Method({
        name: 'dosdata.address.info',
        call: 'explorer',
        params: (args) => ['insight', `addr/${args[0]}`],
        desc: {
            help: 'address info',
            params: "(address)",
            returns: "object",
        }
    }),
    new Method({
        name: 'dosdata.address.balance',
        call: 'explorer',
        params: (args) => ['insight', `addr/${args[0]}/balance`],
        desc: {
            help: 'address balance',
            params: "(address)",
            returns: "number",
        }
    }),
    new Method({
        name: 'dosdata.address.token',
        call: 'explorer',
        params: (args) => ['insight', `addr/${args[0]}/token/${args[1]}`],
        desc: {
            help: 'address contract balance',
            params: "(address,contract)",
            returns: "number",
        }
    }),

    new Interface({
        name: 'transaction.decode',
        call: transaction.decode,
        params: 1,
        desc: {
            help: 'decode transaction',
            params: "(raw:string)",
            returns: "number",
        }
    }),
    new Interface({
        name: 'contract.decode',
        call: contract.decode,
        params: 3,
        desc: {
            help: 'decode contract data',
            params: "(abi: object, tokendata:string/*通过transaction.decode getContractData获取*/)",
            returns: "number",
        }
    }),

];

class Demos {
    constructor(opts) {
        // super();
        this._requestManager = opts.requestManager;

        methods().forEach(k => {
            k.attachToObject(this);
            k.setRequestManager(this._requestManager);
        });
    }
}


global.demos = new Demos({
    requestManager: new RpcEngine()
});

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./contract":96,"./formatters":98,"./interface":100,"./method":102,"./rpcengine":103,"./transaction":104}],100:[function(require,module,exports){
const errors = require("./errors");
const Method = require("./method");
class Interface extends Method {
    constructor(options) {
        super(options);
    }

        
    buildCall() {
        let self = this;
        return async (...args) => {
            this.validateArgs(args);
            if(typeof this.call != "function"){
                throw errors.IS_NOT_A_FUNC;
            }
            return await this.call(...args);
        };
    }

}

module.exports = Interface;
},{"./errors":97,"./method":102}],101:[function(require,module,exports){
const JSONRpc = {
    messageId: 0,
    toPayload (method, params) {
        if (!method)
            console.error('jsonrpc method should be specified!');

        JSONRpc.messageId++;

        return {
            jsonrpc: '2.0',
            id: JSONRpc.messageId,
            method: method,
            params: params || []
        };
    },
    isValidResponse(response){
        return Array.isArray(response) ? response.every(validateSingleMessage) : validateSingleMessage(response);
    },
    toBatchPayload(messages){
        return messages.map(function (message) {
            return JSONRpc.toPayload(message.method, message.params);
        });
    }
}

function validateSingleMessage(message){
  return !!message &&
    !message.error &&
    message.jsonrpc === '2.0' &&
    typeof message.id === 'number' &&
    message.result !== undefined; // only undefined is not valid json object
}

module.exports = JSONRpc;
},{}],102:[function(require,module,exports){
const errors = require("./errors");
const JSONRpc = require("./jsonrpc");
class Method {
    constructor(options) {
        this.name = options.name;
        this.call = options.call;
        this.params = options.params || 0;
        this.inputFormatter = options.inputFormatter;
        this.outputFormatter = options.outputFormatter;
        this.requestManager = null;
        this.desc = options.desc;
    }
    setRequestManager(rm) {
        this.requestManager = rm;
    }
    getCall(args) {
        return (typeof this.call === 'function') ? this.call(args) : this.call;
    }

    getParams(args) {
        return (typeof this.params === 'function') ? this.params(args) : args;
    }

    validateArgs(args) {
        if (this.params >= 0 && args.length !== this.params) {
            throw errors.INVALID_NUMBER_OF_PARAMS;
        }
    }
    formatInput(args) {
        if (!this.inputFormatter) {
            return args;
        }

        return this.inputFormatter.map(function (formatter, index) {
            return formatter ? formatter(args[index]) : args[index];
        });
    }
    formatOutput(result) {
        return this.outputFormatter && result ? this.outputFormatter(result) : result;
    }

    toPayload(args) {
        var params = this.formatInput(args);
        this.validateArgs(params);
        return JSONRpc.toPayload(this.getCall(args), this.getParams(params));
    }
    buildCall() {
        let self = this;
        return async (...args) => {

            var payload = self.toPayload(args);
            let result = await self.requestManager.sendAsync(payload);
            return self.formatOutput(result);
        };
    }

    attachToObject(obj) {
        let func = this.buildCall();
        func.desc = this.desc;
        let names = this.name.split('.');
        if (names.length > 1) {
            for (var i = 0; i < names.length - 1; i++) {
                obj[names[i]] = obj[names[i]] || {};
                obj = obj[names[i]];
            }
            obj[names[names.length - 1]] = func;
        } else {
            obj[names[0]] = func;
        }
    }
}

module.exports = Method;
},{"./errors":97,"./jsonrpc":101}],103:[function(require,module,exports){
(function (global){
class RpcEngine{
    constructor(opts){
        this._events = {};
        this._initEvent();
    }
    _initEvent(){
        global.addEventListener && global.addEventListener("message", (e) => {
            let data;
            try{
                data = JSON.parse(e.data);
            }catch(_){
                data = e.data;
            }
            this._onMessage(data);
        });
    }


    _onMessage(data){
        let { method, id } = data;
        if(!method || !id){
            return;
        }
        this.emit(`${method}:${id}`, data.error && new Error(data.error), data.data);
    }

    once(type, listener) {
        if (typeof listener !== 'function')
            throw new TypeError('"listener" argument must be a function');
          
        this._events[type] || (this._events[type] = []);
        this._events[type].push({
            once: true,
            fn: listener
        });
    };

    emit(type, ...args){
        let listeners = this._events[type];
        if(!listeners) return;
        for (let i = listeners.length - 1; i >= 0; i--) {
            let listener = listeners[i];
            listener.fn(...args);
            if(listener.once)
                listeners.splice(i, i);
        }
    }

    _sendMessage(data){
        window.DemosJS && window.DemosJS.postMessage(JSON.stringify(data));
    }

    sendAsync(data){
        let { method, id } = data;
        return new Promise((resolve, reject) => {
            this.once(`${method}:${id}`, (err, txid) => {
                if(err) return reject(err);
                resolve(txid);
            });
            this._sendMessage(data);
        });
    }
}


module.exports = RpcEngine;
}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],104:[function(require,module,exports){
(function (Buffer){
const {mainnet,testnet3} = require("@demos/chaincfg");
const {MsgTx:DemosMsgTx} = require("@demos/transaction");
const {parseScript,isSideCall} = require("@demos/txscript");
const {SignatureType} = require("@demos/dosec");
const {AddressPubKeyHash} = require("@demos/address");
let currentNet = null;

class MsgTx extends DemosMsgTx{

	static fromBytes(buf){
		let msgTx = new MsgTx();
	    msgTx.deserialize(buf);
	    return msgTx;
	}

	isContract(){
		if(this.txIn.length == 1 && this.txOut.length == 1){
			let pops = parseScript(this.txOut[0].pkScript);
			if(isSideCall(pops)){
				return true;
			}
		}
		return false;
	}

	getAddresses(){
		let addresses = [];

		let len = this.txIn.length;
		if(this.isContract()){
			for (let i = 0; i < len; i++) {
				let hash = this.txIn[i].previousOutPoint.hash.cloneBytes().slice(12);
				let addr = new AddressPubKeyHash(hash, currentNet, SignatureType.STEcdsaSecp256k1);
				addresses.push(addr.encode());
			}
		}

		len = this.txOut.length;
		for (let i = 0; i < len; i++) {
			let pops = parseScript(this.txOut[i].pkScript);
			// console.log(pops);
			let addr = new AddressPubKeyHash(pops[2].data, currentNet, SignatureType.STEcdsaSecp256k1);
			addresses.push(addr.encode());
		}
		return addresses;
	}

	getContractData(){
		if(this.txIn.length == 1 && this.txOut.length == 1){
			let pops = parseScript(this.txOut[0].pkScript);
			if(isSideCall(pops)){
				return pops[3].data.toString("hex");
			}
		}
		throw new Error("Not a contract transaction");
	}
}

module.exports = {
	async decode(raw, net = testnet3){
		currentNet = net;
		let buf = Buffer.from(raw, "hex");
		let msgtx = MsgTx.fromBytes(buf);
		return msgtx;
	}
};
}).call(this,require("buffer").Buffer)
},{"@demos/address":1,"@demos/chaincfg":3,"@demos/dosec":17,"@demos/transaction":28,"@demos/txscript":44,"buffer":62}]},{},[99]);
