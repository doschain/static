(this.webpackJsonpdemos_dapp=this.webpackJsonpdemos_dapp||[]).push([[6],{281:function(t,e,n){"use strict";n.d(e,"e",(function(){return o})),n.d(e,"b",(function(){return c})),n.d(e,"c",(function(){return r})),n.d(e,"d",(function(){return i})),n.d(e,"a",(function(){return u})),n.d(e,"f",(function(){return s})),n.d(e,"g",(function(){return d}));var a="http://proxy-mainnet.doschain.org/insight";function o(t){var e=t.addr,n=t.state,o=t.page,c=t.limit,r=t.category,i="".concat(a,"/v1/api/apps/").concat(e,"/").concat(n,"/?page=").concat(o,"&limit=").concat(c);return r&&(i+="&category=".concat(r)),window.demos.request({method:"GET",url:i})}function c(){return window.demos.request({method:"GET",url:"".concat(a,"/v1/api/category")})}function r(){return window.demos.request({method:"GET",url:"".concat(a,"/v1/api/state")})}function i(t){return window.demos.request({method:"GET",url:"".concat(a,"/v1/api/app/").concat(t)})}function u(t){var e=t.addr,n=t.rawtx,o=t.id,c=t.gain,r=t.code,i=t.mail;return window.demos.request({method:"POST",url:"".concat(a,"/v1/api/app/").concat(e,"/pay"),data:{rawtx:n,id:o,gain:c,code:r,mail:i}})}"games.doschain.org"!==window.location.host&&(a="http://35.220.198.141:8088");var s=function(t){return window.demos.request({method:"GET",url:"".concat(a,"/v1/api/orders/").concat(t)})},d=function(t,e){return window.demos.request({method:"GET",url:"".concat(a,"/v1/api/order/").concat(t,"/").concat(e)})}},282:function(t,e,n){"use strict";var a=n(14),o=n(0);e.a=function(t,e){var n=Object(o.useState)(t),c=Object(a.a)(n,2),r=c[0],i=c[1];return[r,function(t){clearInterval(e),i(t),e=setInterval((function(){t++,i(t)}),1e3)}]}},322:function(t,e,n){t.exports={history:"history_history__2fjli"}},327:function(t,e,n){"use strict";n.r(e);var a=n(14),o=n(0),c=n.n(o),r=n(322),i=n.n(r),u=n(89),s=n(281),d=n(282);e.default=function(t){var e=t.history,n=Object(o.useContext)(u.d).wallet_address,r=Object(o.useState)([]),f=Object(a.a)(r,2),m=f[0],p=f[1],l=Object(o.useState)(!1),h=Object(a.a)(l,2),v=h[0],w=h[1],g=Object(d.a)(0,void 0),b=Object(a.a)(g,2),y=b[0],O=b[1];function j(){var t=!(arguments.length>0&&void 0!==arguments[0])||arguments[0];t&&w(!0),Object(s.f)(n).then((function(e){t&&w(!1),e.ret&&(p((e.data||[]).map((function(t){return t.order_time>=0?t.status=0:t.status=1,1===t.state&&(t.status=2),t}))),O(e.time))}))}return Object(o.useEffect)((function(){n&&j()}),[n]),c.a.createElement(u.a,{title:"DAPP\u7533\u8d2d\u8bb0\u5f55"},v?c.a.createElement("div",{style:{height:"100vh"}},c.a.createElement(u.f,null)):c.a.createElement("div",{className:i.a.history},m.map((function(t){var a=t.id,o=t.name,r=t.logo,i=t.price,s=t.order_time,d=t.status;return c.a.createElement(u.c,{onCD:j,now:y,key:a,id:a,name:o,logo:r,price:i,time:s,status:d,onClick:function(a){e.push("/history_detail/".concat(a)),window.sessionStorage["dapp_".concat(n,"_").concat(a)]=JSON.stringify(t)}})}))))}}}]);