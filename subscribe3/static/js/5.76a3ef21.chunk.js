(this.webpackJsonpdemos_dapp=this.webpackJsonpdemos_dapp||[]).push([[5],{285:function(e,t,a){"use strict";a.d(t,"e",(function(){return r})),a.d(t,"b",(function(){return c})),a.d(t,"c",(function(){return o})),a.d(t,"d",(function(){return u})),a.d(t,"a",(function(){return i})),a.d(t,"f",(function(){return s})),a.d(t,"g",(function(){return d}));var n="https://games.doschain.org/subscribe";function r(e){var t=e.addr,a=e.state,r=e.page,c=e.limit,o=e.category,u="".concat(n,"/v1/api/apps/").concat(t,"/").concat(a,"/?page=").concat(r,"&limit=").concat(c);return o&&(u+="&category=".concat(o)),window.demos.request({method:"GET",url:u})}function c(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/category")})}function o(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/state")})}function u(e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/app/").concat(e)})}function i(e){var t=e.addr,a=e.rawtx,r=e.id,c=e.gain,o=e.code,u=e.mail;return window.demos.request({method:"POST",url:"".concat(n,"/v1/api/app/").concat(t,"/pay"),data:{rawtx:a,id:r,gain:c,code:o,mail:u}})}"games.doschain.org"!==window.location.host&&(n="http://35.220.198.141:8088");var s=function(e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/orders/").concat(e)})},d=function(e,t){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/order/").concat(e,"/").concat(t)})}},289:function(e,t,a){"use strict";a.d(t,"a",(function(){return n})),a.d(t,"b",(function(){return i}));a(12),a(60),a(95),a(96),a(98),a(97),a(0);var n={imgSrc:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/subscribe3","/images")},r=(a(287),a(288)),c=a.n(r),o=a(291),u=a.n(o).a.create({baseURL:"/v1/api/",timeout:1e4});u.interceptors.response.use((function(e){if(e){var t=e.status,a=e.data,n=a.ret,r=a.data,o=void 0===r?null:r;if(200===parseInt(t)){var u={success:n,data:o};return u.success||c.a.fail(u.data,1.5),u}}else c.a.fail("\u8bf7\u6c42\u51fa\u9519",1.5)}),(function(e){return Promise.reject(e)})),u.interceptors.request.use((function(e){if(e.data&&"post"===e.method){e.headers["Content-Type"]="application/x-www-form-urlencoded";var t="";for(var a in e.data)t+=encodeURIComponent(a)+"="+encodeURIComponent(e.data[a])+"&";e.data=t.substring(0,t.length-1)}return e}),(function(e){return Promise.reject(e)}));a(20);var i=function(e){if(!e)return"";var t=e.length;return"".concat(e.substr(0,10),"...").concat(e.substr(t-10,t))}},322:function(e,t,a){e.exports={"dapp-buy":"buy_dapp-buy__SJj5q","dapp-buy__tips":"buy_dapp-buy__tips__WszUk","dapp-buy__timeCount":"buy_dapp-buy__timeCount__21VOe","dapp-buy__form":"buy_dapp-buy__form__1Pl-5","form-item":"buy_form-item__3H34H","form-item__label":"buy_form-item__label__3WJAR","form-item__input":"buy_form-item__input__rxOLz","error-msg":"buy_error-msg__3H_xm",show:"buy_show__3qlA9","btn-buy":"buy_btn-buy__2Oueh",dsb:"buy_dsb__3Mxy_"}},329:function(e,t,a){"use strict";a.r(t);a(287);var n=a(288),r=a.n(n),c=a(12),o=a.n(c),u=a(9),i=a(60),s=a(20),d=a(90),l=a(0),m=a.n(l),p=a(55),b=a.n(p),f=a(322),_=a.n(f),v=a(34),h=a(285),y=a(289),g=a(89),w=function(e){var t=e.data,a=e.cdEndCallback,n=t.order_time,r=t.now_time,c=t.state,o=t.address;return 1!==c?null:m.a.createElement("div",{className:_.a["dapp-buy__timeCount"]},m.a.createElement("h2",null,m.a.createElement(g.b,{text:"\u5269\u4f59\u7533\u8d2d\u65f6\u95f4\uff1a",cdEndCallback:a,time:n,now:r})),m.a.createElement("p",null,"\u5f53\u524d\u7533\u8d2d\u5730\u5740\uff1a".concat(Object(y.b)(o))))},j=function(e){var t,a=e.label,n=e.placeHolder,r=e.type,c=e.msg,o=e.onChange;return m.a.createElement("div",{className:_.a["form-item"]},m.a.createElement("span",{className:_.a["form-item__label"]},a),m.a.createElement("div",{className:_.a["form-item__input"]},m.a.createElement("input",{onChange:function(e){return o(e,r)},placeholder:null!==n&&void 0!==n?n:"\u8bf7\u586b\u5199\u60a8".concat(a)})),m.a.createElement("span",{className:b()((t={},Object(d.a)(t,_.a.show,c),Object(d.a)(t,_.a["error-msg"],1),t))},c))};t.default=function(e){var t,a=e.history,n=e.match.params.id,c=Object(l.useState)(!1),p=Object(s.a)(c,2),f=p[0],y=p[1],O=Object(l.useContext)(g.d),E=Object(l.useState)({gain:"",code:"",mail:""}),x=Object(s.a)(E,2),k=x[0],C=x[1],q=Object(l.useState)([{label:"\u5408\u7ea6\u5730\u5740",type:"gain",msg:""},{label:"\u8054\u7cfb\u90ae\u7bb1",type:"mail",msg:""},{label:"\u63a8\u8350\u5730\u5740",type:"code",placeHolder:"\u63a8\u8350\u5730\u5740\uff08\u53ea\u80fd\u586b\u5199\u77ff\u6c60\u5730\u5740\uff09"}]),N=Object(s.a)(q,2),T=N[0],A=N[1],S=Object(l.useState)({}),G=Object(s.a)(S,2),P=G[0],z=G[1];Object(l.useEffect)((function(){H()}),[]);var H=function(){var e=Object(i.a)(o.a.mark((function e(){var t,a,r,c,i,s;return o.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,Object(h.d)(n);case 2:t=e.sent,a=t.ret,r=t.data,c=void 0===r?{}:r,i=t.time,s=void 0===i?0:i,a&&z(Object(u.a)(Object(u.a)({},c),{},{now_time:s}));case 9:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),R=function(){var e=k.gain,t=k.mail,a="";if(T.forEach((function(e){e.msg&&(a+=e.msg)})),0==a.length){var n=T.map((function(e){return"code"!==e.type&&(e.msg=k[e.type]?"":"".concat(e.label,"\u4e0d\u80fd\u4e3a\u7a7a")),e}));A(n)}return!(!e||!t||0!=a.length)},I=function(){var e=Object(i.a)(o.a.mark((function e(){var t,c,u,i,s,d;return o.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(2!=P.state&&!f){e.next=2;break}return e.abrupt("return");case 2:if(y(!0),R()){e.next=6;break}return y(!1),e.abrupt("return");case 6:return t=k.gain,c=k.code,u=k.mail,e.next=9,window.demos.contractRaw("send",O.contract,[{type:"address",value:O.target_address},{type:"uint256",value:P.price}]).catch((function(e){y(!1)}));case 9:if(i=e.sent){e.next=13;break}return y(!1),e.abrupt("return");case 13:return s={rawtx:i,gain:t,code:c,mail:u,id:parseFloat(n),addr:O.wallet_address},r.a.loading(),e.next=17,Object(h.a)(s).catch((function(e){y(!1)}));case 17:d=e.sent,r.a.hide(),y(!1),(null===d||void 0===d?void 0:d.ret)?r.a.success("\u7533\u8d2ddapp\u6210\u529f",2.5,(function(){a.push("/history")})):r.a.fail((null===d||void 0===d?void 0:d.data)||"\u8bf7\u6c42\u9519\u8bef\uff01",2);case 21:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),J=function(e,t){var a=e.target.value,n=T.slice(),r=T.findIndex((function(e){return t===e.type}));switch(t){case"gain":n[r].msg=function(e){if(!e)return"\u5408\u7ea6\u5730\u5740\u4e0d\u80fd\u4e3a\u7a7a";try{Object(v.decodeAddress)(e)}catch(t){return"\u8bf7\u586b\u5199\u6709\u6548\u7684\u5408\u7ea6\u5730\u5740"}return""}(a);break;case"mail":n[r].msg=function(e){if(!e)return"\u8054\u7cfb\u90ae\u7bb1\u4e0d\u80fd\u4e3a\u7a7a";return/^\w+((.\w+)|(-\w+))@[A-Za-z0-9]+((.|-)[A-Za-z0-9]+).[A-Za-z0-9]+$/.test(e)?"":"\u8bf7\u586b\u5199\u6709\u6548\u7684\u90ae\u7bb1\u5730\u5740"}(a)}"code"!==t&&A(n),C(Object(u.a)(Object(u.a)({},k),{},Object(d.a)({},t,a)))},U=P.order_time,Z=P.now_time,L=P.state,W=P.address;return m.a.createElement(g.e,Object.assign({title:"DAPP\u7533\u8d2d"},e),m.a.createElement("div",{className:b()(Object(d.a)({page:1},_.a["dapp-buy"],1))},m.a.createElement("div",{className:_.a["dapp-buy__tips"]},m.a.createElement("h3",null,"\u7533\u8d2d\u8bf4\u660e"),m.a.createElement("p",null,"1\u3001\u6240\u6709\u77ff\u6c60\u53ef\u4eab\u6709\u7533\u8d2d\u4f18\u5148\u6743\u529b\uff0c\u7533\u8d2d\u5012\u8ba1\u65f6\u7ed3\u675f\u65f6\u5c06\u4f18\u5148\u9009\u62e9\u77ff\u6c60\u4f5c\u4e3adapp\u6240\u6709\u4eba\u3002"),m.a.createElement("p",null,"2\u3001\u7533\u8d2d\u5012\u8ba1\u65f6\u4e8e\u9996\u4e2a\u7533\u8d2d\u4ea7\u751f\u540e24\u4e2a\u5c0f\u65f6\u7ed3\u675f\u3002")),m.a.createElement(w,{data:{order_time:U,now_time:Z,state:L,address:W},cdEndCallback:H}),m.a.createElement("div",{className:_.a["dapp-buy__form"]},T.map((function(e,t){return m.a.createElement(j,Object.assign({},e,{key:e.type,onChange:J}))}))),m.a.createElement("button",{className:b()((t={},Object(d.a)(t,_.a["btn-buy"],1),Object(d.a)(t,_.a.dsb,2===P.state),t)),onClick:I},"\u8d2d\u4e70")))}}}]);