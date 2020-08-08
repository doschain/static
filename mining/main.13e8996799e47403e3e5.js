!function(n){var e={};function t(r){if(e[r])return e[r].exports;var i=e[r]={i:r,l:!1,exports:{}};return n[r].call(i.exports,i,i.exports,t),i.l=!0,i.exports}t.m=n,t.c=e,t.d=function(n,e,r){t.o(n,e)||Object.defineProperty(n,e,{enumerable:!0,get:r})},t.r=function(n){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(n,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(n,"__esModule",{value:!0})},t.t=function(n,e){if(1&e&&(n=t(n)),8&e)return n;if(4&e&&"object"==typeof n&&n&&n.__esModule)return n;var r=Object.create(null);if(t.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:n}),2&e&&"string"!=typeof n)for(var i in n)t.d(r,i,function(e){return n[e]}.bind(null,i));return r},t.n=function(n){var e=n&&n.__esModule?function(){return n.default}:function(){return n};return t.d(e,"a",e),e},t.o=function(n,e){return Object.prototype.hasOwnProperty.call(n,e)},t.p="https://cdn.jsdelivr.net/gh/doschain/static/mining/",t(t.s=1)}([function(n,e,t){var r=function(n){return 0===n?"Number":n&&n.constructor&&n.constructor.toString().match(/function\s*([^(]*)/)[1]},i=function(n,e,t){localStorage[n+"_cache_"+e]=t},o=function(n,e){return localStorage[n+"_cache_"+e]||""},a=function(n,e,t){e.value=o(n,t)};n.exports={getConstructorName:r,obj2Search:r,fetch:function(n,e){return"Object"===r(e)?"Object"===r(e.body)&&("POST"===e.method||"post"===e.method?(e.headers=e.headers||{},e.headers["Content-type"]=e.headers["Content-type"]||"application/json; charset=UTF-8",e.body=JSON.stringify(e.body)):(n+=function(n,e){var t="";for(var r in n)t+=r+"="+n[r]+"&";return("#"===e?"#":"?")+t.substring(0,t.length-1)}(e.body),delete e.body)):e={},fetch(n,e).then((function(n){return n.json()}))},setCacheField:i,restoreCacheField:a,getCacheField:o,initHtmlFontSize:function(){var n=document.getElementsByTagName("html")[0],e=()=>{n.style.fontSize=Math.min(document.body.clientWidth/11.25,66.6)+"px"};window.addEventListener("resize",e,!1),e()},toast:function(n,e){e=isNaN(e)?3e3:e;var t=document.createElement("div");t.innerHTML=n,t.style.cssText="max-width:80%; min-width:80px; padding:10px 14px; word-break:break-all; line-height:1.5; color:rgb(255, 255, 255); text-align:center; border-radius:4px; position:fixed; top:50%; left:50%; transform:translate(-50%, -50%); z-index:999999; background:rgba(0, 0, 0,.7); font-size:16px;",document.body.appendChild(t),setTimeout((function(){t.style.webkitTransition="-webkit-transform 0.5s ease-in, opacity 0.5s ease-in",t.style.opacity="0",setTimeout((function(){document.body.removeChild(t)}),500)}),e)},getAddress:function(){return window.demos.getIdentity()},wrapperInput:function(n,e,t){a(n,e,t),e.addEventListener("click",(function(e){var r=e.target;window.demos.showKeyboard({value:r.value,placeholder:this.getAttribute("placeholder")||"",multiple:!0}).then((function(e){r.value=e,i(n,t,e)}))}),!1)},showLoading:function(){document.getElementById("mask-loading").style="display: block;"},hideLoading:function(){document.getElementById("mask-loading").style="display: none;"},getTxidCache:function(n){return localStorage[`mining_txid_${n}`]||""},setTxidCache:function(n,e){localStorage[`mining_txid_${n}`]=e},removeTxidCache:function(n){delete localStorage[`mining_txid_${n}`]}}},function(n,e,t){var r=t(0),i=t(2),o=t(3);t(4);var a=document.getElementById("price"),s=document.getElementById("percent"),c=document.getElementById("buy"),d=document.getElementById("input-phone"),l=document.getElementById("input-inviter"),u=document.getElementById("progress"),f=document.getElementById("scan"),m=document.getElementById("address"),p=null,g=!1,h="",b=function(){window.demos.scanQRCode().then((function(n){let e=n;n.includes("invite=")&&(e=n.match(/invite=(\w+)/)[1]),l.value=e,r.setCacheField(h,"inputInviter",e)}))},y=function(){if(!g)if(p)if(p.total<=p.remain)r.toast("已售罄");else if(p.price>p.balance)r.toast("余额不足");else{var n=d.value.trim(),e=l.value.trim();n?e&&e===h?r.toast("邀请人不能为收益地址"):window.demos.contract("pay",p.btclight,[{type:"uint256",value:p.price},{type:"string",value:"[4]"}]).then((function(t){r.setTxidCache(h,t),v(h,t,n,e)}),(function(n){r.toast(JSON.stringify(n),3e4)})):r.toast("请填写手机号")}else r.toast("数据获取中，请稍后")},v=function(n,e,t,o){g=!0,r.showLoading(),i.buy(n,e,t,o).then((function(e){g=!1,r.hideLoading(),r.removeTxidCache(n),e.ret?(r.toast("购买成功"),c.innerText="已购买",c.setAttribute("disabled","disabled")):r.toast(e.data)}),(function(n){g=!1,r.hideLoading(),r.toast(JSON.stringify(n),3e4)}))};r.getAddress().then((function(n){var e=n.currency;h=n.address,c.addEventListener("click",y,!1),f.addEventListener("click",b,!1),m.innerText=h,r.wrapperInput(h,d,"inputPhone"),r.wrapperInput(h,l,"inputInviter"),"DOS"===e?h&&i.getStatus(h).then((function(n){n.ret&&(p=n.data,console.log(n.data),function(){a.innerHTML=1e-8*p.price+"BTC";var n=parseInt((p.total-p.remain)/p.total*100);s.innerHTML=n+"%";u.src="https://cdn.jsdelivr.net/gh/doschain/static/mining/"+{0:"images/progress_0.png",1:"images/progress_20.png",2:"images/progress_20.png",3:"images/progress_40.png",4:"images/progress_40.png",5:"images/progress_60.png",6:"images/progress_60.png",7:"images/progress_80.png",8:"images/progress_80.png",9:"images/progress_80.png",10:"images/progress_100.png"}[parseInt(n/10)],p.isbuy&&(c.innerText="已购买",c.setAttribute("disabled","disabled"));var e=r.getTxidCache(h),t=r.getCacheField(h,"inputPhone"),i=r.getCacheField(h,"inputInviter");e&&t&&v(h,e,t,i)}())})):r.toast("请切换到DOS钱包再试",6e4)})),r.initHtmlFontSize(),document.getElementById("root").style="display: block",document.getElementById("version").innerText="version: "+o.version},function(n,e,t){var r=t(0);n.exports={getStatus:function(n){return r.fetch("/mining/api/addr/"+n)},buy:function(n,e,t,i){return r.fetch("/mining/api/addr/"+n+"/buy",{method:"POST",body:{rawtx:e,mobile:t,code:i}})}}},function(n){n.exports=JSON.parse('{"name":"mining","version":"1.0.0","description":"","main":"main.js","scripts":{"dev":"NODE_ENV=development webpack-dev-server --host 0.0.0.0","build":"NODE_ENV=production webpack --mode production"},"author":"","license":"ISC","dependencies":{},"devDependencies":{"css-loader":"^3.4.2","file-loader":"^6.0.0","html-webpack-plugin":"^4.0.0","style-loader":"^1.1.3","url-loader":"^4.0.0","webpack":"^4.42.0","webpack-cli":"^3.3.11","webpack-dev-server":"^3.10.3"}}')},function(n,e,t){var r=t(5),i=t(6);"string"==typeof(i=i.__esModule?i.default:i)&&(i=[[n.i,i,""]]);var o={insert:"head",singleton:!1},a=(r(i,o),i.locals?i.locals:{});n.exports=a},function(n,e,t){"use strict";var r,i=function(){return void 0===r&&(r=Boolean(window&&document&&document.all&&!window.atob)),r},o=function(){var n={};return function(e){if(void 0===n[e]){var t=document.querySelector(e);if(window.HTMLIFrameElement&&t instanceof window.HTMLIFrameElement)try{t=t.contentDocument.head}catch(n){t=null}n[e]=t}return n[e]}}(),a=[];function s(n){for(var e=-1,t=0;t<a.length;t++)if(a[t].identifier===n){e=t;break}return e}function c(n,e){for(var t={},r=[],i=0;i<n.length;i++){var o=n[i],c=e.base?o[0]+e.base:o[0],d=t[c]||0,l="".concat(c," ").concat(d);t[c]=d+1;var u=s(l),f={css:o[1],media:o[2],sourceMap:o[3]};-1!==u?(a[u].references++,a[u].updater(f)):a.push({identifier:l,updater:h(f,e),references:1}),r.push(l)}return r}function d(n){var e=document.createElement("style"),r=n.attributes||{};if(void 0===r.nonce){var i=t.nc;i&&(r.nonce=i)}if(Object.keys(r).forEach((function(n){e.setAttribute(n,r[n])})),"function"==typeof n.insert)n.insert(e);else{var a=o(n.insert||"head");if(!a)throw new Error("Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid.");a.appendChild(e)}return e}var l,u=(l=[],function(n,e){return l[n]=e,l.filter(Boolean).join("\n")});function f(n,e,t,r){var i=t?"":r.media?"@media ".concat(r.media," {").concat(r.css,"}"):r.css;if(n.styleSheet)n.styleSheet.cssText=u(e,i);else{var o=document.createTextNode(i),a=n.childNodes;a[e]&&n.removeChild(a[e]),a.length?n.insertBefore(o,a[e]):n.appendChild(o)}}function m(n,e,t){var r=t.css,i=t.media,o=t.sourceMap;if(i?n.setAttribute("media",i):n.removeAttribute("media"),o&&btoa&&(r+="\n/*# sourceMappingURL=data:application/json;base64,".concat(btoa(unescape(encodeURIComponent(JSON.stringify(o))))," */")),n.styleSheet)n.styleSheet.cssText=r;else{for(;n.firstChild;)n.removeChild(n.firstChild);n.appendChild(document.createTextNode(r))}}var p=null,g=0;function h(n,e){var t,r,i;if(e.singleton){var o=g++;t=p||(p=d(e)),r=f.bind(null,t,o,!1),i=f.bind(null,t,o,!0)}else t=d(e),r=m.bind(null,t,e),i=function(){!function(n){if(null===n.parentNode)return!1;n.parentNode.removeChild(n)}(t)};return r(n),function(e){if(e){if(e.css===n.css&&e.media===n.media&&e.sourceMap===n.sourceMap)return;r(n=e)}else i()}}n.exports=function(n,e){(e=e||{}).singleton||"boolean"==typeof e.singleton||(e.singleton=i());var t=c(n=n||[],e);return function(n){if(n=n||[],"[object Array]"===Object.prototype.toString.call(n)){for(var r=0;r<t.length;r++){var i=s(t[r]);a[i].references--}for(var o=c(n,e),d=0;d<t.length;d++){var l=s(t[d]);0===a[l].references&&(a[l].updater(),a.splice(l,1))}t=o}}}},function(n,e,t){(e=t(7)(!1)).push([n.i,"* {\n    margin: 0;\n}\n\n* :focus{\n    outline: 0;\n}\n\nbody, html{\n    width: 100%;\n    height: 100%;\n    background: #00001e;\n}\n\nbody {\n    margin: 0;\n    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',\n    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',\n    sans-serif;\n    -webkit-font-smoothing: antialiased;\n    -moz-osx-font-smoothing: grayscale;\n}\n\n#root{\n    width: 100%;\n    height: 100%;\n    color: #fff;\n    max-width: 750px;\n    margin: 0 auto;\n    background: url(https://cdn.jsdelivr.net/gh/doschain/static/mining/images/bg.jpg) center #090210 no-repeat;\n    background-size: 100% auto;\n    position: relative;\n}\n\n.header{\n    width: 5.54rem;\n    font-size: 0.45rem;\n    margin: 0 auto;\n    padding-top: 1.8rem;\n    text-align: center;\n    height: 6.2rem;\n    position: relative;\n}\n\n.header img{\n    width: 100%;\n    position: absolute;\n    top: 2.1rem;\n    left: 0;\n}\n\n.header p {\n    z-index: 2;\n    position: relative;\n}\n.header p:last-of-type{\n    margin-top: 4.15rem;\n    font-size: 0.86rem;\n}\n\n.body{\n    margin-top: 0.8rem;\n    text-align: center;\n    font-size: 0.44rem;\n    padding-bottom: 1rem;\n}\n\n.body .price strong {\n    font-size: 0.62rem;\n    color: #b886ff;\n\n}\n\n.body .form{\n    /*width: 9.4rem;*/\n    text-align: left;\n    margin: 1.8rem auto 0 0;\n}\n\n.body .form > div{\n    margin-bottom: 0.6rem;\n}\n\n.body .form strong{\n    font-size: 0.58rem;\n    color: #b886ff;\n}\n\n.body .form label {\n    width: 3.6rem;\n    display: inline-block;\n    text-align: right;\n    white-space: nowrap;\n}\n\n.body .form input {\n    background: #3b1441;\n    border: 1px solid #b1a9b0;\n    border-radius: 0.15rem;\n    height: 0.64rem;\n    font-size: 0.44rem;\n    padding: 0 0.3rem;\n    width: 5rem;\n    color: #fff;\n    vertical-align: top;\n}\n\n.scan{\n    height: 0.58rem;\n    margin-left: 0.13rem;\n    vertical-align: -1px;\n    font-size: 0.3rem;\n}\n\n.body button {\n    width: 3.68rem;\n    height: 0.88rem;\n    background: transparent;\n    border-radius: 0.15rem;\n    border: 2px solid #743ccc;\n    color: #fff;\n    font-size: 0.4rem;\n    margin-top: 1.6rem;\n}\n\n.version{\n    text-align: center;\n    color: #ecc65a;\n    font-size: 12px;\n    margin-top: 1.5rem;\n}\n\n/*.paste{\n\tfont-size: 16px;\n    !* color: #47b1ff; *!\n    border: 1px solid #47b1ff;\n    padding: 3px;\n    border-radius: 5px;\n    display: inline;\n    background-color: #47b1ff;\n}*/\n\n\n.c-mask-loading {\n    position: fixed;\n    width: 100%;\n    height: 100%;\n    top: 0;\n    left: 0;\n    background: rgba(0, 0, 0, .4);\n    z-index: 10000000;\n}\n.c-mask-loading-card{\n     width: 3rem;\n     height: 3rem;\n     background: rgba(0, 0, 0, .7);\n     position: absolute;\n     top: 50%;\n     left: 50%;\n     margin: -1.5rem 0 0 -1.5rem;\n     border-radius: 0.2rem;\n\n }\n\n.c-mask-loading-spin {\n     width: 50px;\n     height: 50px;\n     position: absolute;\n     top: 50%;\n     left: 50%;\n     margin: -25px 0 0 -25px;\n     vertical-align: baseline;\n     animation: weuiLoading 1s steps(12, end) infinite;\n     background: transparent url(\"data:image/svg+xml;charset=utf8, %3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120' viewBox='0 0 100 100'%3E%3Cpath fill='none' d='M0 0h100v100H0z'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23E9E9E9' rx='5' ry='5' transform='translate(0 -30)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23989697' rx='5' ry='5' transform='rotate(30 105.98 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%239B999A' rx='5' ry='5' transform='rotate(60 75.98 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23A3A1A2' rx='5' ry='5' transform='rotate(90 65 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23ABA9AA' rx='5' ry='5' transform='rotate(120 58.66 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23B2B2B2' rx='5' ry='5' transform='rotate(150 54.02 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23BAB8B9' rx='5' ry='5' transform='rotate(180 50 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23C2C0C1' rx='5' ry='5' transform='rotate(-150 45.98 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23CBCBCB' rx='5' ry='5' transform='rotate(-120 41.34 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23D2D2D2' rx='5' ry='5' transform='rotate(-90 35 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23DADADA' rx='5' ry='5' transform='rotate(-60 24.02 65)'/%3E%3Crect width='7' height='20' x='46.5' y='40' fill='%23E2E2E2' rx='5' ry='5' transform='rotate(-30 -5.98 65)'/%3E%3C/svg%3E\") no-repeat;\n     background-size: 100%;\n }\n\n@-webkit-keyframes weuiLoading {\n    0% {\n        transform: rotate3d(0, 0, 1, 0deg);\n    }\n    100% {\n        transform: rotate3d(0, 0, 1, 360deg);\n    }\n}\n@keyframes weuiLoading {\n    0% {\n        transform: rotate3d(0, 0, 1, 0deg);\n    }\n    100% {\n        transform: rotate3d(0, 0, 1, 360deg);\n    }\n}\n\n.input-wrapper{\n    display: inline-block;\n    width: 5.8rem;\n    word-break: break-all;\n    vertical-align: top;\n    font-size: 0.42rem;\n}\n\n\n\n\n\n",""]),n.exports=e},function(n,e,t){"use strict";n.exports=function(n){var e=[];return e.toString=function(){return this.map((function(e){var t=function(n,e){var t=n[1]||"",r=n[3];if(!r)return t;if(e&&"function"==typeof btoa){var i=(a=r,s=btoa(unescape(encodeURIComponent(JSON.stringify(a)))),c="sourceMappingURL=data:application/json;charset=utf-8;base64,".concat(s),"/*# ".concat(c," */")),o=r.sources.map((function(n){return"/*# sourceURL=".concat(r.sourceRoot||"").concat(n," */")}));return[t].concat(o).concat([i]).join("\n")}var a,s,c;return[t].join("\n")}(e,n);return e[2]?"@media ".concat(e[2]," {").concat(t,"}"):t})).join("")},e.i=function(n,t,r){"string"==typeof n&&(n=[[null,n,""]]);var i={};if(r)for(var o=0;o<this.length;o++){var a=this[o][0];null!=a&&(i[a]=!0)}for(var s=0;s<n.length;s++){var c=[].concat(n[s]);r&&i[c[0]]||(t&&(c[2]?c[2]="".concat(t," and ").concat(c[2]):c[2]=t),e.push(c))}},e}}]);