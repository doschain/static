(this.webpackJsonpdemos_dapp=this.webpackJsonpdemos_dapp||[]).push([[8],{285:function(t,e,a){"use strict";a.d(e,"e",(function(){return r})),a.d(e,"b",(function(){return o})),a.d(e,"c",(function(){return c})),a.d(e,"d",(function(){return i})),a.d(e,"a",(function(){return p})),a.d(e,"f",(function(){return d})),a.d(e,"g",(function(){return s}));var n="http://proxy-mainnet.doschain.org/insight";function r(t){var e=t.addr,a=t.state,r=t.page,o=t.limit,c=t.category,i="".concat(n,"/v1/api/apps/").concat(e,"/").concat(a,"/?page=").concat(r,"&limit=").concat(o);return c&&(i+="&category=".concat(c)),window.demos.request({method:"GET",url:i})}function o(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/category")})}function c(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/state")})}function i(t){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/app/").concat(t)})}function p(t){var e=t.addr,a=t.rawtx,r=t.id,o=t.gain,c=t.code,i=t.mail;return window.demos.request({method:"POST",url:"".concat(n,"/v1/api/app/").concat(e,"/pay"),data:{rawtx:a,id:r,gain:o,code:c,mail:i}})}"games.doschain.org"!==window.location.host&&(n="http://35.220.198.141:8088");var d=function(t){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/orders/").concat(t)})},s=function(t,e){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/order/").concat(t,"/").concat(e)})}},321:function(t,e,a){t.exports={"dapp-detail":"dappDetail_dapp-detail__32VWL","dapp-header":"dappDetail_dapp-header__PZpQh","dapp-intro":"dappDetail_dapp-intro__2HCUf","dapp-intro__info":"dappDetail_dapp-intro__info__kPmzm","dapp-intro__info-name":"dappDetail_dapp-intro__info-name__2X5aZ","dapp-intro__info-price":"dappDetail_dapp-intro__info-price__1rqP-","dapp-intro__info-count":"dappDetail_dapp-intro__info-count__1PJef","dapp-intro__content":"dappDetail_dapp-intro__content__2Q8dk","dapp-intro__content-title":"dappDetail_dapp-intro__content-title__2zCaP","dapp-intro__content-img":"dappDetail_dapp-intro__content-img__COK2p","dapp-intro__content-desc":"dappDetail_dapp-intro__content-desc__AdS_1",btnBuy:"dappDetail_btnBuy__60Qvg",dsb:"dappDetail_dsb__jfeiV"}},328:function(t,e,a){"use strict";a.r(e);var n=a(90),r=a(12),o=a.n(r),c=a(9),i=a(60),p=a(20),d=a(0),s=a.n(d),_=a(55),l=a.n(_),u=a(89),m=a(285),f=a(321),h=a.n(f);e.default=function(t){var e,a=t.history,r=t.history.location.search,_=t.match.params.id,f=Object(d.useState)({}),b=Object(p.a)(f,2),v=b[0],E=b[1];Object(d.useEffect)((function(){w()}),[]);var w=function(){var t=Object(i.a)(o.a.mark((function t(){var e,a,n,r,i;return o.a.wrap((function(t){for(;;)switch(t.prev=t.next){case 0:return t.next=2,Object(m.d)(_);case 2:e=t.sent,a=e.ret,n=e.data,r=void 0===n?{}:n,i=e.time,console.log("data",r),a&&E(Object(c.a)(Object(c.a)({},r),{},{price:r.price/1e8,time:i}));case 9:case"end":return t.stop()}}),t)})));return function(){return t.apply(this,arguments)}}(),g=v.logo,D=v.name,y=v.price,N=v.order_time,O=v.time,j=v.state,q=r.substr(1).split("=")[1],P=!0;return P=2!=j&&0==q,s.a.createElement(u.e,{title:"DAPP\u8be6\u60c5",history:a},s.a.createElement("div",{className:l()(Object(n.a)({page:1},h.a["dapp-detail"],1))},s.a.createElement("div",{className:h.a["dapp-header"]},s.a.createElement("div",{className:h.a["dapp-intro"]},s.a.createElement("img",{src:g}),s.a.createElement("div",{className:h.a["dapp-intro__info"]},s.a.createElement("span",{className:h.a["dapp-intro__info-name"]},D),s.a.createElement("span",{className:h.a["dapp-intro__info-price"]},"\u4ef7\u683c\uff1a".concat(null!==y&&void 0!==y?y:"-"," DOS")),1==j&&N>0&&s.a.createElement(u.b,{cdEndCallback:w,className:h.a["dapp-intro__info-count"],time:N,now:O})))),s.a.createElement("div",{className:h.a["dapp-intro__content"]},v.banners&&s.a.createElement(d.Fragment,null,s.a.createElement("h2",{className:h.a["dapp-intro__content-title"]},"\u4ecb\u7ecd"),s.a.createElement("div",{className:h.a["dapp-intro__content-img"]},s.a.createElement("img",{src:v.banners,alt:"dapp intro"}))),s.a.createElement("h2",{className:h.a["dapp-intro__content-title"]},"\u5e94\u7528\u8be6\u60c5"),s.a.createElement("div",{className:h.a["dapp-intro__content-desc"]},s.a.createElement("pre",null,s.a.createElement("p",null,v.describe)))),s.a.createElement("button",{disabled:!P,className:l()((e={},Object(n.a)(e,h.a.btnBuy,1),Object(n.a)(e,h.a.dsb,!P),e)),onClick:function(){return a.push("/dapp_buy/".concat(_))}},P?"\u7533\u8d2d":"\u5df2\u7533\u8d2d")))}}}]);