(this.webpackJsonpdemos_dapp=this.webpackJsonpdemos_dapp||[]).push([[4],{285:function(e,t,a){"use strict";a.d(t,"e",(function(){return r})),a.d(t,"b",(function(){return c})),a.d(t,"c",(function(){return o})),a.d(t,"d",(function(){return u})),a.d(t,"a",(function(){return i})),a.d(t,"f",(function(){return s})),a.d(t,"g",(function(){return d}));var n="http://proxy-mainnet.doschain.org/insight";function r(e){var t=e.addr,a=e.state,r=e.page,c=e.limit,o=e.category,u="".concat(n,"/v1/api/apps/").concat(t,"/").concat(a,"/?page=").concat(r,"&limit=").concat(c);return o&&(u+="&category=".concat(o)),window.demos.request({method:"GET",url:u})}function c(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/category")})}function o(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/state")})}function u(e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/app/").concat(e)})}function i(e){var t=e.addr,a=e.rawtx,r=e.id,c=e.gain,o=e.code,u=e.mail;return window.demos.request({method:"POST",url:"".concat(n,"/v1/api/app/").concat(t,"/pay"),data:{rawtx:a,id:r,gain:c,code:o,mail:u}})}"games.doschain.org"!==window.location.host&&(n="http://35.220.198.141:8088");var s=function(e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/orders/").concat(e)})},d=function(e,t){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/order/").concat(e,"/").concat(t)})}},286:function(e,t,a){"use strict";a.d(t,"a",(function(){return n})),a.d(t,"c",(function(){return i})),a.d(t,"b",(function(){return s}));a(12),a(88),a(92),a(93),a(95),a(94),a(0);var n={imgSrc:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/subscribe","/images")},r=(a(287),a(288)),c=a.n(r),o=a(289),u=a.n(o).a.create({baseURL:"/v1/api/",timeout:1e4});u.interceptors.response.use((function(e){if(e){var t=e.status,a=e.data,n=a.ret,r=a.data,o=void 0===r?null:r;if(200===parseInt(t)){var u={success:n,data:o};return u.success||c.a.fail(u.data,1.5),u}}else c.a.fail("\u8bf7\u6c42\u51fa\u9519",1.5)}),(function(e){return Promise.reject(e)})),u.interceptors.request.use((function(e){if(e.data&&"post"===e.method){e.headers["Content-Type"]="application/x-www-form-urlencoded";var t="";for(var a in e.data)t+=encodeURIComponent(a)+"="+encodeURIComponent(e.data[a])+"&";e.data=t.substring(0,t.length-1)}return e}),(function(e){return Promise.reject(e)}));a(87);function i(e,t){var a=arguments.length>2&&void 0!==arguments[2]?arguments[2]:1,n=e*a,r=n+86400*a,c=t*a-r;return c>0?null:[c,r]}var s=function(e){if(!e)return"";var t=e.length;return"".concat(e.substr(0,10),"...").concat(e.substr(t-10,t))}},320:function(e,t,a){e.exports={"dapp-buy":"buy_dapp-buy__SJj5q","dapp-buy__tips":"buy_dapp-buy__tips__WszUk","dapp-buy__timeCount":"buy_dapp-buy__timeCount__21VOe","dapp-buy__form":"buy_dapp-buy__form__1Pl-5","form-item":"buy_form-item__3H34H","form-item__label":"buy_form-item__label__3WJAR","form-item__input":"buy_form-item__input__rxOLz","error-msg":"buy_error-msg__3H_xm",show:"buy_show__3qlA9","btn-buy":"buy_btn-buy__2Oueh",dsb:"buy_dsb__3Mxy_"}},325:function(e,t,a){"use strict";a.r(t);a(287);var n=a(288),r=a.n(n),c=a(12),o=a.n(c),u=a(19),i=a(88),s=a(87),d=a(90),l=a(0),m=a.n(l),p=a(54),b=a.n(p),f=a(320),_=a.n(f),g=a(33),v=a(285),y=a(286),h=a(89),w=function(e){var t=e.data,a=t.order_time,n=t.now_time,r=t.state,c=t.address;return 1!==r?null:m.a.createElement("div",{className:_.a["dapp-buy__timeCount"]},m.a.createElement("h2",null,"\u5269\u4f59\u7533\u8d2d\u65f6\u95f4:",m.a.createElement(h.b,{order_time:a,now:n})),m.a.createElement("p",null,"\u5f53\u524d\u7533\u8d2d\u5730\u5740\uff1a".concat(Object(y.b)(c))))},j=function(e){var t,a=e.label,n=e.placeHolder,r=e.type,c=e.msg,o=e.onChange;return m.a.createElement("div",{className:_.a["form-item"]},m.a.createElement("span",{className:_.a["form-item__label"]},a),m.a.createElement("div",{className:_.a["form-item__input"]},m.a.createElement("input",{onChange:function(e){return o(e,r)},placeholder:null!==n&&void 0!==n?n:"\u8bf7\u586b\u5199\u60a8".concat(a)})),m.a.createElement("span",{className:b()((t={},Object(d.a)(t,_.a.show,c),Object(d.a)(t,_.a["error-msg"],1),t))},c))};t.default=function e(t){var a=t.history,n=t.match.params.id,c=Object(l.useContext)(h.d),p=Object(l.useState)({gain:"",code:"",mail:""}),f=Object(s.a)(p,2),y=f[0],O=f[1],E=Object(l.useState)([{label:"\u5408\u7ea6\u5730\u5740",type:"gain",msg:""},{label:"\u8054\u7cfb\u90ae\u7bb1",type:"mail",msg:""},{label:"\u63a8\u8350\u5730\u5740",type:"code",placeHolder:"\u63a8\u8350\u5730\u5740\uff08\u53ea\u80fd\u586b\u5199\u77ff\u6c60\u5730\u5740\uff09"}]),x=Object(s.a)(E,2),k=x[0],C=x[1],q=Object(l.useState)({}),N=Object(s.a)(q,2),T=N[0],S=N[1];Object(l.useEffect)((function(){(function(){var e=Object(i.a)(o.a.mark((function e(){var t,a,r,c,i,s;return o.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,Object(v.d)(n);case 2:t=e.sent,a=t.ret,r=t.data,c=void 0===r?{}:r,i=t.time,s=void 0===i?0:i,console.log("data",c,"time",s),a&&S(Object(u.a)(Object(u.a)({},c),{},{now_time:s}));case 10:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}})()()}),[]);var A=function(){var e=y.gain,t=y.mail,a="";if(k.forEach((function(e){e.msg&&(a+=e.msg)})),0==a.length){var n=k.map((function(e){return"code"!==e.type&&(e.msg=y[e.type]?"":"".concat(e.label,"\u4e0d\u80fd\u4e3a\u7a7a")),e}));C(n)}return!(!e||!t||0!=a.length)},G=function(){var t=Object(i.a)(o.a.mark((function t(){var u,i,s,d,l,m;return o.a.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:if(!e.lock){t.next=2;break}return t.abrupt("return");case 2:if(e.lock=!0,A()){t.next=6;break}return e.lock=null,t.abrupt("return");case 6:return u=y.gain,i=y.code,s=y.mail,t.next=9,window.demos.contractRaw("send",c.contract,[{type:"address",value:c.target_address},{type:"uint256",value:T.price}]).catch((function(t){e.lock=null}));case 9:if(d=t.sent){t.next=13;break}return e.lock=null,t.abrupt("return");case 13:return l={rawtx:d,gain:u,code:i,mail:s,id:parseFloat(n),addr:c.wallet_address},console.log("params",l),r.a.loading(),t.next=18,Object(v.a)(l).catch((function(t){console.log(t),e.lock=null}));case 18:m=t.sent,console.log("res-buy",m),r.a.hide(),e.lock=null,(null===m||void 0===m?void 0:m.ret)?r.a.success("\u7533\u8d2ddapp\u6210\u529f",2.5,(function(){a.push("/history")})):r.a.fail((null===m||void 0===m?void 0:m.data)||"\u8bf7\u6c42\u9519\u8bef\uff01",2);case 23:case"end":return t.stop()}}),t)})));return function(){return t.apply(this,arguments)}}(),z=function(e,t){var a=e.target.value,n=k.slice(),r=k.findIndex((function(e){return t===e.type}));switch(t){case"gain":n[r].msg=function(e){if(!e)return"\u5408\u7ea6\u5730\u5740\u4e0d\u80fd\u4e3a\u7a7a";try{Object(g.decodeAddress)(e)}catch(t){return"\u8bf7\u586b\u5199\u6709\u6548\u7684\u5408\u7ea6\u5730\u5740"}return""}(a);break;case"mail":n[r].msg=function(e){if(!e)return"\u8054\u7cfb\u90ae\u7bb1\u4e0d\u80fd\u4e3a\u7a7a";return/^\w+((.\w+)|(-\w+))@[A-Za-z0-9]+((.|-)[A-Za-z0-9]+).[A-Za-z0-9]+$/.test(e)?"":"\u8bf7\u586b\u5199\u6709\u6548\u7684\u90ae\u7bb1\u5730\u5740"}(a)}"code"!==t&&C(n),O(Object(u.a)(Object(u.a)({},y),{},Object(d.a)({},t,a)))},H=T.order_time,R=T.now_time,I=T.state;return console.log("buy-globalStore",c),m.a.createElement(h.e,Object.assign({title:"Dapp\u7533\u8d2d"},t),m.a.createElement("div",{className:b()(Object(d.a)({page:1},_.a["dapp-buy"],1))},m.a.createElement("div",{className:_.a["dapp-buy__tips"]},m.a.createElement("h3",null,"\u7533\u8d2d\u8bf4\u660e"),m.a.createElement("p",null,"1\u3001\u6240\u6709\u77ff\u6c60\u53ef\u4eab\u6709\u7533\u8d2d\u4f18\u5148\u6743\u529b\uff0c\u7533\u8d2d\u5012\u8ba1\u65f6\u7ed3\u675f\u65f6\u5c06\u4f18\u5148\u9009\u62e9\u77ff\u6c60\u4f5c\u4e3adapp\u6240\u6709\u4eba\u3002"),m.a.createElement("p",null,"2\u3001\u7533\u8d2d\u5012\u8ba1\u65f6\u4e8e\u9996\u4e2a\u7533\u8d2d\u4ea7\u751f\u540e24\u4e2a\u5c0f\u65f6\u7ed3\u675f\u3002")),m.a.createElement(w,{data:{order_time:H,now_time:R,state:I,address:c.wallet_address}}),m.a.createElement("div",{className:_.a["dapp-buy__form"]},k.map((function(e,t){return m.a.createElement(j,Object.assign({},e,{key:e.type,onChange:z}))}))),m.a.createElement("button",{className:_.a["btn-buy"],onClick:G},"\u8d2d\u4e70")))}}}]);