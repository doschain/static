(this.webpackJsonpdemos_dapp=this.webpackJsonpdemos_dapp||[]).push([[4],{281:function(e,t,a){"use strict";a.d(t,"e",(function(){return r})),a.d(t,"b",(function(){return o})),a.d(t,"c",(function(){return c})),a.d(t,"d",(function(){return i})),a.d(t,"a",(function(){return s})),a.d(t,"f",(function(){return u})),a.d(t,"g",(function(){return m}));var n="http://proxy-mainnet.doschain.org/insight";function r(e){var t=e.addr,a=e.state,r=e.page,o=e.limit,c=e.category,i="".concat(n,"/v1/api/apps/").concat(t,"/").concat(a,"/?page=").concat(r,"&limit=").concat(o);return c&&(i+="&category=".concat(c)),window.demos.request({method:"GET",url:i})}function o(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/category")})}function c(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/state")})}function i(e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/app/").concat(e)})}function s(e){var t=e.addr,a=e.rawtx,r=e.id,o=e.gain,c=e.code,i=e.mail;return window.demos.request({method:"POST",url:"".concat(n,"/v1/api/app/").concat(t,"/pay"),data:{rawtx:a,id:r,gain:o,code:c,mail:i}})}"games.doschain.org"!==window.location.host&&(n="http://35.220.198.141:8088");var u=function(e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/orders/").concat(e)})},m=function(e,t){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/order/").concat(e,"/").concat(t)})}},282:function(e,t,a){"use strict";var n=a(40),r=a(0);t.a=function(e,t){var a=Object(r.useState)(e),o=Object(n.a)(a,2),c=o[0],i=o[1];return[c,function(e){clearInterval(t),i(e),t=setInterval((function(){e++,i(e)}),1e3)}]}},285:function(e,t,a){"use strict";a.d(t,"a",(function(){return n})),a.d(t,"b",(function(){return s}));a(13),a(88),a(286),a(287),a(299),a(298),a(0);var n={imgSrc:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/subscribe2","/images")},r=(a(283),a(284)),o=a.n(r),c=a(289),i=a.n(c).a.create({baseURL:"/v1/api/",timeout:1e4});i.interceptors.response.use((function(e){if(e){var t=e.status,a=e.data,n=a.ret,r=a.data,c=void 0===r?null:r;if(200===parseInt(t)){var i={success:n,data:c};return i.success||o.a.fail(i.data,1.5),i}}else o.a.fail("\u8bf7\u6c42\u51fa\u9519",1.5)}),(function(e){return Promise.reject(e)})),i.interceptors.request.use((function(e){if(e.data&&"post"===e.method){e.headers["Content-Type"]="application/x-www-form-urlencoded";var t="";for(var a in e.data)t+=encodeURIComponent(a)+"="+encodeURIComponent(e.data[a])+"&";e.data=t.substring(0,t.length-1)}return e}),(function(e){return Promise.reject(e)}));a(40);var s=function(e){if(!e)return"";var t=e.length;return"".concat(e.substr(0,10),"...").concat(e.substr(t-10,t))}},319:function(e,t,a){e.exports={home:"home_home__3lina","home-title":"home_home-title__3DRdN","home-tab":"home_home-tab__fwBi0","home-tab__container":"home_home-tab__container__cts_r","home-tab__container-button":"home_home-tab__container-button__1pJcS",leftButton:"home_leftButton__2r89s",active:"home_active__24_TE",rightButton:"home_rightButton__2cofC",unActive:"home_unActive__R7YBJ","home-tab__container-tag":"home_home-tab__container-tag__1YD1_","home-dapp":"home_home-dapp__3cnl7","home-dapp__developing":"home_home-dapp__developing__3bRYP","home-dapp__list":"home_home-dapp__list__2AV6S","home-dapp__card":"home_home-dapp__card__eeGZW","home-dapp__card-logo":"home_home-dapp__card-logo__8xUUz","home-dapp__card-info":"home_home-dapp__card-info__22UEW","dapp-name":"home_dapp-name__2l-ag","dapp-price":"home_dapp-price__3chBD","home-dapp__card-countDown":"home_home-dapp__card-countDown__pGBi_",dsb:"home_dsb__1PRwr","no-data":"home_no-data__1MTmR","go-history":"home_go-history__2zGtU"}},329:function(e,t,a){"use strict";a.r(t);var n=a(13),r=a.n(n),o=a(85);var c=a(96);function i(e){return function(e){if(Array.isArray(e))return Object(o.a)(e)}(e)||function(e){if("undefined"!==typeof Symbol&&Symbol.iterator in Object(e))return Array.from(e)}(e)||Object(c.a)(e)||function(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}()}var s=a(12),u=a(88),m=a(40),d=a(90),l=a(0),p=a.n(l),_=a(97),h=a(55),f=a.n(h),b=a(285),v=a(281),g=a(89),E=a(319),w=a.n(E),j=a(282),O=function(e){var t=e.text,a=e.className,n=e.onTap,r=void 0===n?function(){}:n;return p.a.createElement("button",{className:a,onClick:r},t)},y=function(e){var t=e.data;return p.a.createElement("div",{className:w.a["home-dapp__developing"]},(null===t||void 0===t?void 0:t.name)?p.a.createElement(l.Fragment,null,p.a.createElement("p",null,"\u5f53\u524d\u5f00\u53d1\u4efb\u52a1: ".concat(t.name)),p.a.createElement("p",null,"\u9884\u8ba1\u5b8c\u6210\uff1a".concat(t.time))):p.a.createElement("p",{style:{marginTop:"0.18rem"}},"\u6682\u65e0\u5f00\u53d1\u4e2dDapp"))},N=function(e){var t=e.data,a=void 0===t?{}:t,n=e.history,r=e.curTab,o=e.now,c=a.id,i=a.name,s=a.logo,u=a.price,m=a.order_time,l=a.state;return p.a.createElement("div",{className:w.a["home-dapp__card"]},p.a.createElement(_.b,{to:"/dapp_detail/".concat(c,"/?tab=").concat(r)},p.a.createElement("img",{className:w.a["home-dapp__card-logo"],alt:"dapp",src:s}),p.a.createElement("div",{className:w.a["home-dapp__card-info"]},p.a.createElement("span",{className:w.a["dapp-name"]},i),p.a.createElement("span",{className:w.a["dapp-price"]},"".concat(u," DOS")))),0===r&&1==l&&p.a.createElement("div",{className:w.a["home-dapp__card-countDown"]},p.a.createElement(g.b,{time:m,now:o})),p.a.createElement("button",{className:f()(Object(d.a)({},w.a.dsb,1===r)),disabled:1===r,onClick:function(){n.push("/dapp_buy/".concat(c))}},"\u7acb\u5373\u7533\u8d2d"))},S=function(e){var t=e.loading,a=e.list,n=e.curTab,r=e.history,o=e.now;return t?p.a.createElement(g.f,null):0===a.length?p.a.createElement("div",{className:w.a["no-data"]},p.a.createElement("img",{src:"".concat(b.a.imgSrc,"/no_data.png"),alt:""}),p.a.createElement("span",null,"\u6682\u65e0\u76f8\u5173\u6570\u636e")):p.a.createElement(l.Fragment,null,a.map((function(e){return p.a.createElement(N,{data:e,history:r,curTab:n,noe:o,key:e.id.toString()})})))};t.default=function(e){var t,a,n=Object(l.useContext)(g.d),o=Object(l.useState)(-1),c=Object(m.a)(o,2),h=c[0],b=c[1],E=Object(l.useState)(0),N=Object(m.a)(E,2),T=N[0],x=N[1],k=Object(l.useState)([{id:-1,name:"\u5168\u90e8"}]),B=Object(m.a)(k,2),C=B[0],G=B[1],q=Object(l.useState)(!0),A=Object(m.a)(q,2),D=A[0],I=A[1],R=Object(j.a)(0,void 0),U=Object(m.a)(R,2),P=U[0],J=U[1],Y=Object(l.useState)(null),z=Object(m.a)(Y,2),F=z[0],W=z[1];Object(l.useEffect)((function(){K(),Q()}),[]);var L=Object(l.useState)({list:[],page:1,limit:10,total:0}),M=Object(m.a)(L,2),V=M[0],Z=M[1];Object(l.useEffect)((function(){H()}),[n.wallet_address]);var H=function(){var e=Object(u.a)(r.a.mark((function e(t){var a,o,c,u,m,d;return r.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return a=Object(s.a)({addr:n.wallet_address,state:0,page:1,limit:100,category:null},t),I(!0),e.next=4,Object(v.e)(a);case 4:if(o=e.sent,c=o.ret,u=o.data,m=o.time,J(m),I(!1),c&&u){e.next=12;break}return e.abrupt("return");case 12:(d={page:u.page,total:u.total,list:1===(null===t||void 0===t?void 0:t.page)?i(u.list):[].concat(i(V.list),i(u.list))}).list=d.list.map((function(e){return e.price=e.price/1e8,e.now=m,e})),console.log(d.list[0]),Z(d);case 16:case"end":return e.stop()}}),e)})));return function(t){return e.apply(this,arguments)}}(),K=function(){var e=Object(u.a)(r.a.mark((function e(){var t,a,o;return r.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,Object(v.c)();case 2:t=e.sent,a=t.ret,o=t.data,a&&W({name:o.name,time:o.time}),n.updateStore({target_address:o.address,contract:o.contract});case 7:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),Q=function(){var e=Object(u.a)(r.a.mark((function e(){var t,a,n,o;return r.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,Object(v.b)();case 2:if(t=e.sent,a=t.ret,n=t.data,o=void 0===n?[]:n,a&&0!==o.length){e.next=8;break}return e.abrupt("return");case 8:G([].concat(i(C),i(o)));case 9:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),X=function(e){x(e),H({page:1,category:null,state:parseInt(e)})};return p.a.createElement("div",{className:w.a.home},p.a.createElement(_.b,{className:w.a["go-history"],to:"/history"},"\u7533\u8d2d\u8bb0\u5f55>"),p.a.createElement("div",{className:w.a["home-title"]}),p.a.createElement("div",{className:w.a["home-tab"]},p.a.createElement("div",{className:w.a["home-tab__container"]},p.a.createElement("div",{className:w.a["home-tab__container-button"]},p.a.createElement("button",{className:f()((t={},Object(d.a)(t,w.a.leftButton,1),Object(d.a)(t,0===T?w.a.active:w.a.unActive,1),t)),onClick:function(){return X(0)}},"\u5f85\u7533\u8d2d"),p.a.createElement("button",{className:f()((a={},Object(d.a)(a,w.a.rightButton,1),Object(d.a)(a,1===T?w.a.active:w.a.unActive,1),a)),onClick:function(){return X(1)}},"\u5df2\u7533\u8d2d")),p.a.createElement("div",{className:w.a["home-tab__container-tag"]},C.map((function(e,t){var a=e.name,n=e.id;return p.a.createElement(O,{className:f()(Object(d.a)({},w.a.active,n===h)),key:n.toString(),text:a,onTap:function(){var e;(e=n)!==h&&(b(e),H({page:1,category:-1===e?null:e}))}})}))))),p.a.createElement("div",{className:w.a["home-dapp"]},p.a.createElement(y,{data:F}),p.a.createElement("div",{className:w.a["home-dapp__list"]},p.a.createElement(S,Object.assign({},e,{curTab:T,loading:D,list:V.list,now:P})))))}}}]);
//# sourceMappingURL=4.69df7271.chunk.js.map