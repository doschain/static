(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
module.exports = {
    INVALID_NUMBER_OF_PARAMS: new Error('Invalid number of input parameters'),
    
    INVALID_PROVIDER: new Error('Provider not set or invalid'),
    INVALID_RESPONSE: (result) => {
        var message = !!result && !!result.error && !!result.error.message ? result.error.message : 'Invalid JSON RPC response: ' + JSON.stringify(result);
        return new Error(message);
    },
    CONNECTION_TIMEOUT: (ms) => {
    	return new Error('CONNECTION TIMEOUT: timeout of ' + ms + ' ms achived')
    }
}
},{}],2:[function(require,module,exports){

module.exports = {
	inputAddressFormatter(address){
		return address;
	},
	transferFormatter(data){
		return data.transactionHash || data;
	}
}
},{}],3:[function(require,module,exports){
(function (global){
const Method = require("./method");
const RpcEngine = require("./rpcengine");
const formatters = require("./formatters");

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
},{"./formatters":2,"./method":5,"./rpcengine":6}],4:[function(require,module,exports){
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
},{}],5:[function(require,module,exports){
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
},{"./errors":1,"./jsonrpc":4}],6:[function(require,module,exports){
(function (global){
class RpcEngine{
    constructor(opts){
        this._events = {};
        this._initEvent();
    }
    _initEvent(){
        global.addEventListener("message", (e) => {
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
},{}]},{},[3]);
