(this.webpackJsonpdemos_dapp=this.webpackJsonpdemos_dapp||[]).push([[8],{285:function(a,t,e){"use strict";e.d(t,"e",(function(){return c})),e.d(t,"b",(function(){return o})),e.d(t,"c",(function(){return r})),e.d(t,"d",(function(){return i})),e.d(t,"a",(function(){return p})),e.d(t,"f",(function(){return d})),e.d(t,"g",(function(){return s}));var n="https://games.doschain.org/subscribe";function c(a){var t=a.addr,e=a.state,c=a.page,o=a.limit,r=a.category,i="".concat(n,"/v1/api/apps/").concat(t,"/").concat(e,"?page=").concat(c,"&limit=").concat(o);return r&&(i+="&category=".concat(r)),window.demos.request({method:"GET",url:i})}function o(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/category")})}function r(){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/state")})}function i(a){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/app/").concat(a)})}function p(a){var t=a.addr,e=a.rawtx,c=a.id,o=a.gain,r=a.code,i=a.mail;return window.demos.request({method:"POST",url:"".concat(n,"/v1/api/app/").concat(t,"/pay"),data:{rawtx:e,id:c,gain:o,code:r,mail:i}})}"games.doschain.org"!==window.location.host&&(n="http://35.220.198.141:8088");var d=function(a){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/orders/").concat(a)})},s=function(a,t){return window.demos.request({method:"GET",url:"".concat(n,"/v1/api/order/").concat(a,"/").concat(t)})}},321:function(a,t,e){a.exports={"dapp-detail":"dappDetail_dapp-detail__32VWL","dapp-header":"dappDetail_dapp-header__PZpQh","dapp-intro":"dappDetail_dapp-intro__2HCUf",logo:"dappDetail_logo__1LGui","dapp-intro__info":"dappDetail_dapp-intro__info__kPmzm","dapp-intro__info-name":"dappDetail_dapp-intro__info-name__2X5aZ","dapp-intro__info-price":"dappDetail_dapp-intro__info-price__1rqP-","dapp-intro__info-count":"dappDetail_dapp-intro__info-count__1PJef","dapp-intro__content":"dappDetail_dapp-intro__content__2Q8dk","dapp-intro__content-title":"dappDetail_dapp-intro__content-title__2zCaP","dapp-intro__content-img":"dappDetail_dapp-intro__content-img__COK2p","dapp-intro__content-desc":"dappDetail_dapp-intro__content-desc__AdS_1",btnBuy:"dappDetail_btnBuy__60Qvg",able:"dappDetail_able__MAtYo"}},328:function(a,t,e){"use strict";e.r(t);var n=e(90),c=e(12),o=e.n(c),r=e(9),i=e(60),p=e(20),d=e(0),s=e.n(d),_=e(55),l=e.n(_),u=e(89),m=e(285),f=e(321),b=e.n(f);t.default=function(a){var t,e=a.history,c=a.history.location.search,_=a.match.params.id,f=Object(d.useState)({}),h=Object(p.a)(f,2),v=h[0],g=h[1];Object(d.useEffect)((function(){E()}),[]);var E=function(){var a=Object(i.a)(o.a.mark((function a(){var t,e,n,c,i;return o.a.wrap((function(a){for(;;)switch(a.prev=a.next){case 0:return a.next=2,Object(m.d)(_);case 2:t=a.sent,e=t.ret,n=t.data,c=void 0===n?{}:n,i=t.time,e&&g(Object(r.a)(Object(r.a)({},c),{},{price:c.price/1e8,time:i}));case 8:case"end":return a.stop()}}),a)})));return function(){return a.apply(this,arguments)}}(),w=v.logo,D=v.name,N=v.price,k=v.order_time,y=v.time,O=v.state,j=v.banners,q=c.substr(1).split("=")[1],P=!1,G="";switch(P=0===parseInt(q)&&(0===O||1===O),O){case 0:case 1:G="\u7533\u8d2d";break;case 2:G="\u5df2\u7533\u8d2d";break;case 3:G="\u5f00\u53d1\u4e2d";break;case 4:G="\u6682\u672a\u5f00\u653e\u7533\u8d2d";break;default:G=""}return s.a.createElement(u.a,{title:"DAPP\u8be6\u60c5"},s.a.createElement("div",{className:l()(Object(n.a)({page:1},b.a["dapp-detail"],1))},s.a.createElement("div",{className:b.a["dapp-header"]},s.a.createElement("div",{className:b.a["dapp-intro"]},s.a.createElement("div",{className:b.a.logo,style:{backgroundImage:"url(".concat(w,")")}}),s.a.createElement("div",{className:b.a["dapp-intro__info"]},s.a.createElement("span",{className:b.a["dapp-intro__info-name"]},D),s.a.createElement("span",{className:b.a["dapp-intro__info-price"]},"\u4ef7\u683c\uff1a".concat(null!==N&&void 0!==N?N:"-"," DOS")),1==O&&k>0&&s.a.createElement(u.b,{cdEndCallback:E,className:b.a["dapp-intro__info-count"],time:k,now:y})))),s.a.createElement("div",{className:b.a["dapp-intro__content"]},s.a.createElement("h2",{className:b.a["dapp-intro__content-title"]},"\u4ecb\u7ecd"),s.a.createElement("div",{className:b.a["dapp-intro__content-img"],style:{backgroundImage:"url(".concat(j,")")}}),s.a.createElement("h2",{className:b.a["dapp-intro__content-title"]},"\u5e94\u7528\u8be6\u60c5"),s.a.createElement("div",{className:b.a["dapp-intro__content-desc"]},s.a.createElement("pre",null,s.a.createElement("p",null,v.describe)))),s.a.createElement("button",{disabled:!P,className:l()((t={},Object(n.a)(t,b.a.btnBuy,1),Object(n.a)(t,b.a.able,P),t)),onClick:function(){return e.push("/dapp_buy/".concat(_))}},G)))}}}]);