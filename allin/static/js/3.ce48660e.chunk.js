(this.webpackJsonputxo=this.webpackJsonputxo||[]).push([[3],{72:function(e,t,n){},73:function(e,t,n){"use strict";n.r(t);var a=n(10),c=n(0),r=n.n(c),l=(n(72),n(15)),u=n(12),s=n(8),o=n.n(s),i=n(11),m=window.apiHost;function p(){return(p=Object(i.a)(o.a.mark((function e(t){return o.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.abrupt("return",new Promise(function(){var e=Object(i.a)(o.a.mark((function e(n,a){var c;return o.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.prev=0,e.next=3,t;case 3:c=e.sent,n(JSON.parse(c)),e.next=10;break;case 7:e.prev=7,e.t0=e.catch(0),a(e.t0);case 10:case"end":return e.stop()}}),e,null,[[0,7]])})));return function(t,n){return e.apply(this,arguments)}}()));case 1:case"end":return e.stop()}}),e)})))).apply(this,arguments)}var E=function(e,t){return function(e){return p.apply(this,arguments)}(window.demos.allin.submit(e,t,"",""))};t.default=Object(l.c)()((function(e){var t=e.address,n=Object(c.useState)(null),s=Object(a.a)(n,2),o=s[0],i=s[1],p=Object(c.useState)(1),f=Object(a.a)(p,2),b=f[0],d=f[1],v=Object(c.useState)(!1),w=Object(a.a)(v,2),O=w[0],j=w[1];function k(){(function(e){return window.demos.request({method:"GET",url:"".concat(m,"/api/").concat(e,"/state")})})(t).then((function(e){e.ret&&i(e.data)}))}return Object(c.useEffect)((function(){t&&k()}),[t]),o?r.a.createElement("div",{className:"p-home"},r.a.createElement("div",{className:"block1"},r.a.createElement("div",null,r.a.createElement("p",null,"\u5956\u6c60\u91d1\u989d"),r.a.createElement("strong",null,o.total)),r.a.createElement("div",null,r.a.createElement("p",null,"KEY\u5206\u7ea2"),r.a.createElement("strong",null,o.total*o["key-scale"]/100))),r.a.createElement("div",{className:"block2"},r.a.createElement("div",{className:"time"},function(e){var t=new Date(1e3*e);return"".concat(Object(u.a)(t.getHours()),":").concat(Object(u.a)(t.getMinutes()),":").concat(Object(u.a)(t.getSeconds()))}(o.settle)),r.a.createElement("div",{className:"row row1"},r.a.createElement("p",null,"KEY\u4ef7\u683c: ",o.price),r.a.createElement("div",null,r.a.createElement("p",{onClick:function(){d(b+1)}},"\u52a01"),r.a.createElement("p",{onClick:function(){d(b+10)}},"\u52a010"))),r.a.createElement("div",{className:"row"},r.a.createElement("p",null,"\u6211\u7684KEY: ",o.keys)),r.a.createElement("div",{className:"row row3"},r.a.createElement("p",null,"\u6700\u540e\u4e00\u540d\u73a9\u5bb6:"),r.a.createElement("p",null,o["last-key"]))),r.a.createElement("div",{className:"block3"},r.a.createElement("p",null,"\u8d2d\u4e70\u6570\u91cf: ",b),r.a.createElement("button",{onClick:function(){if(t&&o)if(o.status){var e=o.price*b+o["price-step"]*(b-1)*b/2;j(!0),E(e,b).then((function(e){j(!1),e.ret?(Object(u.c)("\u8d2d\u4e70\u6210\u529f"),k()):Object(u.c)(e.data,6e3)}),(function(e){j(!1)}))}else Object(u.c)("\u7ed3\u7b97\u4e2d\uff0c\u8bf7\u7a0d\u540e\u518d\u8bd5")}},"\u8d2d\u4e70")),O&&r.a.createElement(l.b,null)):r.a.createElement("div",null)}))}}]);