(this.webpackJsonpdapp_collection=this.webpackJsonpdapp_collection||[]).push([[0],{103:function(e,n,t){},104:function(e,n,t){"use strict";t.r(n);var a=t(0),r=t.n(a),c=t(43),i=t.n(c),o=t(11),l=t(3),u=t(14),s=t(5),d=t(30),f=t(21),p=t(105),m=t(44),g=t.n(m);t(74);var h=function(e){var n=e.children,t=e.config,a=void 0===t?{}:t;if(!n)return null;var c=Object(o.a)({dots:!1,infinite:!0,speed:500,autoplaySpeed:5e3,slidesToShow:1,slidesToScroll:1,arrows:!1,autoplay:!1,accessibility:!1},a);return r.a.createElement(g.a,c,n)},b=t(1),v=t(2);function j(){var e=Object(b.a)(["\n  padding-top: ",";\n  padding-left: ",";\n  padding-bottom: ",";\n  padding-right: ",";\n  box-sizing: ",";\n"]);return j=function(){return e},e}function E(){var e=Object(b.a)(["\n  display: flex;\n  width: ",";\n  flex-direction: ",";\n  align-items: ",";\n  justify-content: ",";\n"]);return E=function(){return e},e}var _=v.a.div(E(),(function(e){return e.width||"100%"}),(function(e){return e.dir||"row"}),(function(e){return e.align||"start"}),(function(e){return e.justify||"flex-start"})),w=v.a.div(j(),(function(e){return e.top||".3rem"}),(function(e){return e.left||".3rem"}),(function(e){return e.bottom||".3rem"}),(function(e){return e.right||".3rem"}),(function(e){return e.boxSize||"border-box"}));function O(){var e=Object(b.a)(["\n  display: block;\n  width: 100%;\n  height: 100%;\n"]);return O=function(){return e},e}function y(){var e=Object(b.a)(["\n  display: inline-block;\n  width: ",";\n  height: ",";\n  border-radius: ",";\n  overflow: hidden;\n"]);return y=function(){return e},e}var k=v.a.i(y(),(function(e){return e.width}),(function(e){return e.height}),(function(e){return e.radius})),x=v.a.img(O()),S=function(e){var n=e.onClick,t=e.width,a=e.height,c=e.radius,i=e.icon,o=e.size;return r.a.createElement(k,{radius:c||0,width:o||t||".24rem",height:o||a||t||".24rem",onClick:function(e){n&&"function"===typeof n&&(e.preventDefault(),e.stopPropagation(),n())}},r.a.createElement(x,{src:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/dapp_collection_test","/images/").concat(i,".png"),alt:""}))};function z(){var e=Object(b.a)(["\n  display: flex;\n  justify-content: space-between;\n  align: center;\n  min-width: 2rem;\n"]);return z=function(){return e},e}function C(){var e=Object(b.a)(["\n  display: flex;\n  justify-content: center;\n  align-items: center;\n  min-width: 0.9rem;\n  font-size: 0.3rem;\n  color: #99a1bd;\n  text-decoration: none;\n"]);return C=function(){return e},e}function A(){var e=Object(b.a)(["\n  min-width: 0.69rem;\n  // height: 0.34rem;\n  font-size: 0.36rem;\n  font-family: PingFang SC;\n  font-weight: 500;\n  color: #313131;\n  line-height: 0.42rem;\n  &.unblur {\n    font-size: 0.3rem;\n    color: #99a1bd;\n  }\n"]);return A=function(){return e},e}var D=v.a.div(A()),N=Object(v.a)(u.b)(C()),T=v.a.div(z()),L=function(e){var n=e.tabs,t=void 0===n?[]:n,a=e.id,c=e.current,i=e.onTab,o=e.showMore,l=e.moreText;return r.a.createElement(w,{top:"0",bottom:"0"},r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement(T,null,t.map((function(e,n){return r.a.createElement(D,{key:e.toString(),onClick:function(){i&&"function"===typeof i&&i(n)},className:n!==c?"unblur":null,style:{marginLeft:1===n?".24rem":0}},e)}))),o&&r.a.createElement(N,{to:"/list/".concat(i?"local":a)},r.a.createElement("span",null,l),r.a.createElement(S,{width:".3rem",icon:"right_arrow"}))),r.a.createElement("div",null,e.children))},I=t(13),B=(t(52),r.a.createContext(null));function F(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:null;try{var t=window.localStorage.getItem(e);return t=t?JSON.parse(t):n}catch(a){return n}}function M(e){var n=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"";try{return!!e&&(window.localStorage.setItem(e,JSON.stringify(n)),!0)}catch(t){return!1}}function P(){var e=Object(b.a)(["\n  width: 100%;\n  height: 1px;\n  margin-top: 0.43rem;\n  background: #f2f2f2;\n"]);return P=function(){return e},e}function W(){var e=Object(b.a)(["\n  text-decoration: none;\n  -webkit-tap-highlight-color: transparent;\n"]);return W=function(){return e},e}function J(){var e=Object(b.a)(["\n  flex-grow: 1;\n  display: flex;\n  flex-direction: column;\n  justify-content: center;\n  padding-left: 0.3rem;\n  box-sizing: border-box;\n"]);return J=function(){return e},e}function R(){var e=Object(b.a)(["\n  display: -webkit-box;\n  -webkit-box-orient: vertical;\n  -webkit-line-clamp: 2;\n  font-size: 0.24rem;\n  line-height: 1.5;\n  font-weight: 500;\n  color: #99a1bd;\n  margin-top: 0.15rem;\n  overflow: hidden;\n"]);return R=function(){return e},e}function U(){var e=Object(b.a)(["\n  display: block;\n  color: #313131;\n  text-overflow: ellipsis;\n  white-space: nowrap;\n  overflow: hidden;\n  margin-top: ",";\n  margin-bottom: ",";\n  width: ",";\n  text-align: ",";\n  font-size: ",";\n"]);return U=function(){return e},e}function V(){var e=Object(b.a)(["\n  display: inline-block;\n  width: 1.2rem;\n  height: 1.2rem;\n  border-radius: 0.16rem;\n  outline: 0;\n  box-shadow: 0px 0.13rem 0.17rem 0.01rem rgba(177, 177, 177, 0.28);\n"]);return V=function(){return e},e}var Y=v.a.img(V()),q=v.a.span(U(),(function(e){return e.mt||0}),(function(e){return e.mb||0}),(function(e){return e.width||"100%"}),(function(e){return e.align||"left"}),(function(e){return e.fontSize||"0.26rem"})),G=v.a.p(R()),H=v.a.div(J()),K=v.a.a(W()),Q=function(e,n){return n.findIndex((function(n){return n.name===e.name}))},X=function(e){var n=e.app,t=Object(a.useContext)(B).update;return r.a.createElement(K,{onClick:function(){var e=F("local_marked_app_link",[]);Q(n,e)>-1?window.open(n.apply_url):t({visitApp:n,showConfirmDailog:!0})}},r.a.createElement(_,{justify:"center",dir:"column"},r.a.createElement(Y,{src:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/dapp_collection_test","/images/test_a.jpeg")}),r.a.createElement(q,{width:"1.2rem",align:"center",mt:".24rem"},null===n||void 0===n?void 0:n.name)))},Z=v.a.div(P()),$=function(e){var n=e.data,t=Object(a.useContext)(B),c=t.update,i=t.localSavedApps,o=Q(n,i);return r.a.createElement(K,{onClick:function(){var e=F("local_marked_app_link",[]);Q(n,e)>-1?window.open(n.apply_url):c({visitApp:n,showConfirmDailog:!0})}},r.a.createElement(_,null,r.a.createElement(Y,{src:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/dapp_collection_test","/images/test_a.jpeg")}),r.a.createElement(H,null,r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement(q,{width:"4.5rem"},null===n||void 0===n?void 0:n.name),r.a.createElement(S,{onClick:function(){var e=F("local_saved_apps",[]),t=Q(n,e);t<0?e=[].concat(Object(I.a)(e),[n]):e.splice(t,1),M("local_saved_apps",e)&&c({localSavedApps:e})},size:".36rem",icon:o>-1?"icon_star_active":"icon_star"})),r.a.createElement(G,null,null===n||void 0===n?void 0:n.describe),r.a.createElement(Z,null))))};function ee(){var e=Object(b.a)(["\n  display: ",";\n  grid-template-columns: ",";\n  grid-row-gap: ",";\n  padding: ",";\n"]);return ee=function(){return e},e}var ne=v.a.div(ee(),(function(e){return e.type||"grid"}),(function(e){return e.column||"100%"}),(function(e){return e.rowGrap||".28rem"}),(function(e){return e.padding||".36rem 0"}));function te(){var e=Object(b.a)(["\n  width: 100%;\n  height: 1.2rem;\n  display: flex;\n  justify-content: center;\n  align-items: center;\n  color: #99a1bd;\n  font-size: 0.24rem;\n  padding: ",";\n"]);return te=function(){return e},e}var ae=v.a.div(te(),(function(e){return e.padding||0}));function re(){var e=Object(b.a)(["\n  display: flex;\n  flex-direction: column;\n  width: 100vw;\n  height: 100vh;\n  background: ",";\n"]);return re=function(){return e},e}var ce=v.a.div(re(),(function(e){return e.color||"#ffffff"}));function ie(){var e=Object(b.a)(["\n  display: inline-block;\n  width: 0.5rem;\n  height: 0.5rem;\n  animation: "," 1.5s linear infinite;\n  text-align: center;\n  background: url(","/images/icon_loading_02.png)\n    no-repeat center center;\n  background-size: contain;\n"]);return ie=function(){return e},e}function oe(){var e=Object(b.a)(["\n  from {\n    transform: rotate(0deg);\n  }\n\n  to {\n    transform: rotate(360deg);\n  }\n"]);return oe=function(){return e},e}function le(){var e=Object(b.a)(["\n  position: fixed;\n  top: 0;\n  left: 0;\n  width: 100vw;\n  height: 100vh;\n  background: rgba(0, 0, 0, ",");\n  display: flex;\n  align-items: center;\n  justify-content: center;\n"]);return le=function(){return e},e}var ue=v.a.div(le(),(function(e){return e.opacity||".1"})),se=Object(v.b)(oe()),de=v.a.div(ie(),se,"https://cdn.jsdelivr.net/gh/doschain/static/dapp_collection_test"),fe=function(e){return e.loading?r.a.createElement(de,null):null},pe=function(e){return r.a.createElement(ue,{opacity:e.opacity||.01},r.a.createElement(de,null))},me=t(27),ge=t.n(me);t(80);var he=function(){var e=Object(a.useContext)(B),n=e.visitApp,t=e.showConfirmDailog,c=e.update,i=Object(a.useState)(!1),o=Object(l.a)(i,2),u=o[0],s=o[1],d=Object(a.useState)(!1),f=Object(l.a)(d,2),p=f[0],m=f[1],g=Object(a.useState)(!1),h=Object(l.a)(g,2),b=h[0],v=h[1];return Object(a.useEffect)((function(){t?(v(!0),setTimeout((function(){m(!0)}),200)):(m(!1),setTimeout((function(){v(!1)}),200))}),[t]),r.a.createElement(ue,{id:"c-mark",opacity:".25",style:{display:b?"block":"none"}},r.a.createElement("div",{id:"c-box",className:"c-box__container",style:{transform:"translateY(".concat(p?"0":"100%",")")}},r.a.createElement("span",{className:"title"},"\u8bbf\u95ee\u8bf4\u660e"),r.a.createElement("div",{className:"c-box__content"},r.a.createElement(Y,{src:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/dapp_collection_test","/images/test_a.jpeg")}),r.a.createElement("h3",null,"\u4f60\u6b63\u5728\u8bbf\u95ee\u7b2c\u4e09\u65b9Dapp"),r.a.createElement("p",null,"\u60a8\u5728\u7b2c\u4e09\u65b9Dapp\u4e0a\u7684\u4f7f\u7528\u884c\u4e3a\u4f7f\u7528\u8be5\u7b2c\u4e09\u65b9Dapp\u7684\u300a\u7528\u6237\u534f\u8bae\u300b\u548c\u300a\u9690\u79c1\u653f\u7b56\u300b\u7531".concat(null===n||void 0===n?void 0:n.name,"\u76f4\u63a5\u5e76\u5355\u72ec\u5411\u60a8\u627f\u62c5\u8d23\u4efb"))),r.a.createElement("a",{className:"c-box__check",onClick:function(){s(!u)}},r.a.createElement(S,{width:".36rem",height:".38rem",icon:u?"icon_checked":"icon_unchecked"}),r.a.createElement("span",null,"\u4e0b\u6b21\u4e0d\u518d\u63d0\u793a")),r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement("button",{className:"c-box__button",onClick:function(){if(u){var e=F("local_marked_app_link",[]);e.push(n),M("local_marked_app_link",e)}s(!1),c({showConfirmDailog:!1})}},"\u53d6\u6d88"),r.a.createElement("button",{className:"c-box__button",onClick:function(){if(u){var e=F("local_marked_app_link",[]);e.push(n),M("local_marked_app_link",e)}s(!1),c({showConfirmDailog:!1}),window.open(n.apply_url)}},"\u786e\u5b9a"))))},be={en:{translation:{t_title:"title",h_input_placeholder:"Search or enter the DApp URL",h_favorite:"Favorite",h_recently:"Recently",h_all:"More",h_lang:"Languages",h_search:"Search",no_data:"No data",cancel:"Cancel",not_find_app:"DApp not found",search_results:"Search results"}},cn:{translation:{t_title:"title",h_input_placeholder:"\u641c\u7d22\u6216\u8f93\u5165DApp\u7f51\u5740",h_favorite:"\u6536\u85cf",h_recently:"\u6700\u8fd1",h_all:"\u5168\u90e8",h_lang:"\u591a\u8bed\u8a00\u8bbe\u7f6e",h_search:"\u641c\u7d22",no_data:"\u6682\u65e0\u6570\u636e",cancel:"\u53d6\u6d88",not_find_app:"\u641c\u7d22\u4e0d\u5230\u8be5\u5e94\u7528",search_results:"\u641c\u7d22\u7ed3\u679c"}}},ve=t(4),je=t.n(ve),Ee=t(7),_e=t(48),we=t.n(_e),Oe="https://games.doschain.org/dapp_collection";"games.doschain.org"!==window.location.host&&(Oe="https://games-testnet.doschain.org/dapp_collection");var ye=we.a.create({baseURL:Oe,timeout:1e4});ye.interceptors.response.use((function(e){return 200!==e.data.code&&alert("netWork error"),{code:e.data.code,data:e.data.data||null}}),(function(e){return Promise.reject(e)})),ye.interceptors.request.use((function(e){return e}),(function(e){return Promise.reject(e)}));var ke=ye,xe=function(){var e=Object(Ee.a)(je.a.mark((function e(){return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,ke.get("/v1/api/banners");case 2:return e.abrupt("return",e.sent);case 3:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),Se=function(){var e=Object(Ee.a)(je.a.mark((function e(){return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,ke.get("/v1/api/category");case 2:return e.abrupt("return",e.sent);case 3:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),ze=function(){var e=Object(Ee.a)(je.a.mark((function e(){var n,t,a,r,c,i,o,l,u=arguments;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n=u.length>0&&void 0!==u[0]?u[0]:{},t=n.id,a=n.page,r=void 0===a?1:a,c=n.limit,i=void 0===c?10:c,o=n.lang,void 0===o?null:o,l="/v1/api/apps?page=".concat(r,"&limit=").concat(i,"&category=").concat(t),e.next=4,ke.get(l);case 4:return e.abrupt("return",e.sent);case 5:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),Ce=function(){var e=Object(Ee.a)(je.a.mark((function e(){var n,t,a,r,c,i,o,l,u,s=arguments;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return n=s.length>0&&void 0!==s[0]?s[0]:{},t=n.word,a=void 0===t?"":t,r=n.page,c=void 0===r?1:r,i=n.limit,o=void 0===i?10:i,l=n.lang,void 0===l?1:l,u="/v1/api/appsearch/".concat(a,"?page=").concat(c,"&limit=").concat(o),e.next=4,ke.get(u);case 4:return e.abrupt("return",e.sent);case 5:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),Ae=function(){var e=Object(Ee.a)(je.a.mark((function e(n,t){var a,r,c,i;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:a=n.code,r=n.data,200===a&&t&&"function"===typeof t&&(c=(null===r||void 0===r?void 0:r.list)||[],i={page:(null===r||void 0===r?void 0:r.page)||1,total:(null===r||void 0===r?void 0:r.total)||0},t({list:c,pager:i}));case 2:case"end":return e.stop()}}),e)})));return function(n,t){return e.apply(this,arguments)}}(),De=function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:{},n=e.id,t=e.page,r=void 0===t?1:t,c=e.limit,i=void 0===c?10:c,u=e.language,s=void 0===u?1:u,d=Object(a.useState)(!0),f=Object(l.a)(d,2),p=f[0],m=f[1],g=Object(a.useState)([]),h=Object(l.a)(g,2),b=h[0],v=h[1],j=Object(a.useState)({page:1,total:0}),E=Object(l.a)(j,2),_=E[0],w=E[1],O=function(){var e=Object(Ee.a)(je.a.mark((function e(){var t;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,ze({id:n,page:r,limit:i,language:s});case 2:t=e.sent,m(!1),Ae(t,(function(e){var t=e.list,a=e.pager,r=[].concat(Object(I.a)(b),Object(I.a)(t)).map((function(e,t){return Object(o.a)(Object(o.a)({},e),{},{id:b.length+1+t,parentId:n})}));v(r),w(a)}));case 5:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}();return Object(a.useEffect)((function(){n&&O(n)}),[n]),[b,_,p]};function Ne(){var e=Object(b.a)(["\n  padding: 0.3rem 0.3rem 0.45rem;\n  // border-top: 1px solid #f2f2f2;\n  // box-shadow: -4px 0px 5px 0 #f2f2f2;\n"]);return Ne=function(){return e},e}function Te(){var e=Object(b.a)(["\n  display: inline-block;\n  font-size: 0.3rem;\n  color: #313131;\n  font-weight: 500;\n  margin-left: 0.3rem;\n"]);return Te=function(){return e},e}function Le(){var e=Object(b.a)(["\n  min-height: 100%;\n  // margin-top: 0.4rem;\n  border-radius: 0.6rem 0.6rem 0 0;\n  background: #ffffff;\n  // box-shadow: 0px -0.1rem 0.42rem 0.7rem rgba(78, 113, 255, 0.36);\n  z-index: 10;\n  background: #ffffff;\n"]);return Le=function(){return e},e}function Ie(){var e=Object(b.a)(["\n  position: relative;\n  height: calc(100vh - 1.27rem);\n  padding-top: 0.4rem;\n  overflow-y: auto;\n  overflow-x: hidden;\n"]);return Ie=function(){return e},e}function Be(){var e=Object(b.a)(["\n  width: 6.9rem;\n  padding: 0.42rem 0 0.15rem;\n  height: 0.7rem;\n  margin: 0 auto;\n\n  // background: linear-gradient(0deg, #486af3 0%, #6d88f5 100%);\n"]);return Be=function(){return e},e}function Fe(){var e=Object(b.a)(["\n  display: inline-block;\n  height: 0.3rem;\n  line-height: 0.3rem;\n  text-align: center;\n  font-size: 0.3rem;\n  color: ",";\n  background: transparent;\n  border: none;\n  outline: 0;\n  padding: 0;\n"]);return Fe=function(){return e},e}function Me(){var e=Object(b.a)(["\n  display: block;\n  width: 5.45rem;\n  height: 0.7rem;\n  line-height: 0.7rem;\n  color: #fff;\n  font-size: 0.3rem;\n  border-radius: 0.35rem;\n  padding-left: 0.4rem;\n  padding-right: 0.4rem;\n  box-sizing: border-box;\n  text-decoration: none;\n  background: rgba(255, 255, 255, 0.2);\n"]);return Me=function(){return e},e}function Pe(){var e=Object(b.a)(["\n  display: inline-block;\n  width: 100%;\n  height: 2.88rem;\n  outline: 0;\n  background: #ccc url(",") no-repeat center;\n  background-size: cover;\n  border-radius: 0.3rem;\n  overflow: hidden;\n  text-decoration: none;\n  -webkit-tap-highlight-color: transparent;\n"]);return Pe=function(){return e},e}var We=v.a.a(Pe(),(function(e){return e.img})),Je=Object(v.a)(u.b)(Me()),Re=v.a.button(Fe(),(function(e){return e.color||"#ffffff"})),Ue=v.a.div(Be()),Ve=v.a.div(Ie()),Ye=v.a.div(Le()),qe=v.a.span(Te()),Ge=v.a.div(Ne()),He=function(e){var n=e._t;return r.a.createElement(Ge,null,r.a.createElement(u.b,{to:"/lang"},r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement(_,{align:"center"},r.a.createElement(S,{size:".34rem",icon:"icon_lang"}),r.a.createElement(qe,null,n("h_lang"))),r.a.createElement(S,{size:".3rem",icon:"right_arrow"}))))},Ke=function(e){var n=e.data,t=void 0===n?[]:n;return r.a.createElement(w,{top:".54rem"},r.a.createElement(h,{config:{autoplay:!0,dots:!0}},t.map((function(e,n){return r.a.createElement(We,{href:e.url,target:"_blank",img:e.picture,key:n.toString()})}))))},Qe=function(e){var n=e.history,t=Object(a.useContext)(B),c=Object(a.useState)(0),i=Object(l.a)(c,2),o=i[0],u=i[1],s=0===o,d=s?Object(I.a)(t.localSavedApps):Object(I.a)(t.recentVisitedApps),f=t._t;return r.a.createElement(L,{tabs:[f("h_favorite"),f("h_recently")],showMore:d.length>0,moreText:f("h_all"),history:n,current:o,onTab:function(e){u(e)}},0===d.length?r.a.createElement(ae,{padding:".56rem 0"},s?"\u6682\u65e0\u6536\u85cf":"\u6682\u65e0\u6700\u8fd1\u6d4f\u89c8\u6570\u636e"):r.a.createElement(ne,{grid:"inline-grid",column:"repeat(4,auto)"},d.slice(0,4).map((function(e,n){return r.a.createElement(X,{app:e,key:n.toString()})}))))},Xe=function(e){var n=e.title,t=e.id,a=e._t,c=De({id:t,limit:5}),i=Object(l.a)(c,3),o=i[0],u=(i[1],i[2]);return r.a.createElement(L,{tabs:[n],id:t,showMore:o.length>0,moreText:a("h_all")},r.a.createElement(ne,null,u?r.a.createElement(ae,null,r.a.createElement(fe,{loading:!0})):0===o.length?r.a.createElement(ae,null,a("no_data")):o.map((function(e){return r.a.createElement($,{key:e.name,data:e})}))))},Ze=function(e){var n=e.history,t=function(){var e=Object(a.useState)([]),n=Object(l.a)(e,2),t=n[0],r=n[1],c=function(){var e=Object(Ee.a)(je.a.mark((function e(){var n,t,a;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,Se();case 2:n=e.sent,t=n.code,a=n.data,200===t&&r(a);case 6:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}();return Object(a.useEffect)((function(){c()}),[]),[t]}(),c=Object(l.a)(t,1)[0],i=Object(a.useContext)(B)._t,o=Object(a.useState)([1]),u=Object(l.a)(o,2),s=u[0],d=u[1];return Object(a.useEffect)((function(){(function(){var e=Object(Ee.a)(je.a.mark((function e(){var n,t;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return e.next=2,xe();case 2:n=e.sent,t=n.data,200===n.code&&d(t);case 6:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}})()()}),[]),r.a.createElement(r.a.Fragment,null,r.a.createElement(ce,{color:"linear-gradient(0deg, #486AF3 0%, #6D88F5 2%)"},r.a.createElement(Ue,null,r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement(S,{size:".38rem",icon:"scan"}),r.a.createElement(Je,{to:"/search"},i("h_input_placeholder")),r.a.createElement(Re,{onClick:function(){n.push("/search")}},i("h_search")))),r.a.createElement(Ve,null,r.a.createElement(Ye,null,r.a.createElement(Ke,{data:s}),r.a.createElement(Qe,e),c.map((function(e){return r.a.createElement(Xe,{key:e.name,id:e.id,title:e.name,_t:i})})),r.a.createElement(He,{_t:i})))),r.a.createElement(he,null))},$e=function(e){var n=Object(a.useContext)(B).localSavedApps;return r.a.createElement(ne,null,0===n.length?r.a.createElement(ae,null,"\u6682\u65e0\u6570\u636e"):n.map((function(e){return r.a.createElement($,{key:e.name,data:e})})))},en=function(e){var n=e.id,t=De({id:parseInt(n)}),c=Object(l.a)(t,3),i=c[0],o=(c[1],c[2]);return r.a.createElement(a.Fragment,null,r.a.createElement(ne,null,0!==i.length||o?i.map((function(e){return r.a.createElement($,{key:e.name,data:e})})):r.a.createElement(ae,null,"\u6682\u65e0\u6570\u636e")),o&&r.a.createElement(pe,null))},nn=function(e){var n=e.match.params.id;return r.a.createElement(ce,null,r.a.createElement(w,null,"local"===n?r.a.createElement($e,null):r.a.createElement(en,{id:n})))};function tn(){var e=Object(b.a)(["\n  min-height: 90%;\n  z-index: 10;\n"]);return tn=function(){return e},e}function an(){var e=Object(b.a)(["\n  position: relative;\n  border-bottom: 1px solid #f2f2f2;\n  padding: 0.24rem 0;\n"]);return an=function(){return e},e}function rn(){var e=Object(b.a)(["\n  display: inline-block;\n  font-size: ",";\n  color: ",";\n"]);return rn=function(){return e},e}function cn(){var e=Object(b.a)(["\n  position: absolute;\n  top: 50%;\n  right: 0.2rem;\n  transform: translateY(-50%);\n  width: 0.48rem;\n  height: 0.48rem;\n  display: flex;\n  align-items: center;\n  justify-content: center;\n"]);return cn=function(){return e},e}function on(){var e=Object(b.a)(["\n  position: relative;\n  overflow: hidden;\n"]);return on=function(){return e},e}function ln(){var e=Object(b.a)(["\n  display: block;\n  width: 5.9rem;\n  height: 0.7rem;\n  color: #99a1bd;\n  outline: 0;\n  border: 0.01rem solid #99a1bd;\n  border-radius: 0.35rem;\n  padding-left: 0.4rem;\n  padding-right: 0.4rem;\n  font-size: 0.28rem;\n  box-sizing: border-box;\n  background: transparent;\n  &::-webkit-input-placeholder {\n    color: #99a1bd;\n  }\n"]);return ln=function(){return e},e}var un=v.a.input(ln()),sn=v.a.div(on()),dn=v.a.div(cn()),fn=v.a.span(rn(),(function(e){return e.fontSize||".24rem"}),(function(e){return e.color||"#99A1BD"})),pn=(v.a.div(an()),v.a.div(tn())),mn=function(e){var n=e.history,t=Object(a.useContext)(B)._t,c=Object(a.useState)([]),i=Object(l.a)(c,2),o=i[0],u=i[1],s=Object(a.useState)({page:1,total:0}),d=Object(l.a)(s,2),f=d[0],p=d[1],m=Object(a.useState)(!1),g=Object(l.a)(m,2),h=g[0],b=g[1],v=Object(a.useState)(!1),j=Object(l.a)(v,2),E=j[0],O=j[1],y=Object(a.useState)(null),k=Object(l.a)(y,2),x=k[0],z=k[1],C=function(){var e=Object(Ee.a)(je.a.mark((function e(){var n,t;return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:if(!h){e.next=2;break}return e.abrupt("return");case 2:return b(!0),O(!1),n=document.getElementById("keyWord").value||null,z(n),e.next=8,Ce({word:n,page:f.page});case 8:t=e.sent,b(!1),Ae(t,(function(e){var n=e.list,t=e.pager;u(n),p(t),O(0===n.length)}));case 11:case"end":return e.stop()}}),e)})));return function(){return e.apply(this,arguments)}}(),A=ge.a.debounce(C,200);return r.a.createElement(ce,null,r.a.createElement(Ue,null,r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement(sn,null,r.a.createElement(un,{id:"keyWord",placeholder:t("h_input_placeholder"),onChange:A}),x&&r.a.createElement(dn,{onClick:function(){document.getElementById("keyWord").value="",u([]),O(!1)}},r.a.createElement(S,{size:".3rem",icon:"input_clear"}))),r.a.createElement(Re,{onClick:function(){n.go(-1)},color:"#99a1bd"},t("cancel")))),r.a.createElement(Ve,null,r.a.createElement(pn,null,r.a.createElement(w,null,r.a.createElement("p",{style:{fontSize:".28rem",color:"#99A1BD"}},t("search_results")),!h&&E&&x?r.a.createElement(_,{justify:"center",dir:"column",align:"center"},r.a.createElement("img",{src:"".concat("https://cdn.jsdelivr.net/gh/doschain/static/dapp_collection_test","/images/search_no_data.png"),style:{width:"1rem",margin:".4rem 0 .2rem"},alt:t("not_find_app")}),r.a.createElement(fn,null,t("not_find_app"))):r.a.createElement(ne,{dir:"row"},o.map((function(e){return r.a.createElement($,{key:e.name,data:e})})))))),h&&r.a.createElement(pe,null))};function gn(){var e=Object(b.a)(["\n  padding: 0.3rem;\n  border-bottom: 1px solid #f2f2f2;\n"]);return gn=function(){return e},e}function hn(){var e=Object(b.a)(["\n  display: inline-block;\n  color: #313131;\n  font-size: 0.28rem;\n"]);return hn=function(){return e},e}var bn=v.a.span(hn()),vn=v.a.div(gn()),jn=[{name:"\u7b80\u4f53\u4e2d\u6587",lang:"cn"},{name:"English",lang:"en"},{name:"\u65e5\u672c\u8a9e",lang:"jp"},{name:"\ud55c\uae00",lang:"sk"}],En=function(e){var n=Object(p.a)().i18n,t=Object(a.useState)(F("dapp_collection_lang","cn")),c=Object(l.a)(t,2),i=c[0],o=c[1],u=function(){var e=Object(Ee.a)(je.a.mark((function e(t){return je.a.wrap((function(e){for(;;)switch(e.prev=e.next){case 0:return o(t),e.next=3,n.changeLanguage(t);case 3:M("dapp_collection_lang",t);case 4:case"end":return e.stop()}}),e)})));return function(n){return e.apply(this,arguments)}}();return r.a.createElement(ce,null,jn.map((function(e){var n=e.name,t=e.lang;return r.a.createElement(vn,{onClick:function(){return u(t)},key:t},r.a.createElement(_,{justify:"space-between",align:"center"},r.a.createElement(bn,null,n),i===t&&r.a.createElement(S,{size:".3rem",icon:"icon_selected"})))})))};d.a.use(f.e).init({resources:be,lng:"en",fallbackLng:"en",debug:!1,interpolation:{escapeValue:!1}});var _n=function(){var e=Object(a.useState)(Object(o.a)(Object(o.a)({},function(){try{return{localSavedApps:F("local_saved_apps",[]),recentVisitedApps:F("local_recent_visited_apps",[]),markedUnConfirmAppLink:F("local_marked_app_link",[])}}catch(e){}}()),{},{visitApp:null,showConfirmDailog:!1})),n=Object(l.a)(e,2),t=n[0],c=n[1],i=Object(p.a)().t;return Object(a.useEffect)((function(){var e=F("dapp_collection_lang")||"cn";d.a.changeLanguage(e)}),[]),r.a.createElement(B.Provider,{value:Object(o.a)(Object(o.a)({},t),{},{update:function(e){c(Object(o.a)(Object(o.a)({},t),e))},_t:i})},r.a.createElement(a.Suspense,{fallback:null},r.a.createElement(u.a,null,r.a.createElement(s.c,null,r.a.createElement(s.a,{exact:!0,strict:!0,path:"/",component:Ze}),r.a.createElement(s.a,{exact:!0,strict:!0,path:"/search",component:mn}),r.a.createElement(s.a,{exact:!0,strict:!0,path:"/list/:id",component:nn}),r.a.createElement(s.a,{exact:!0,strict:!0,path:"/lang",component:En})))),r.a.createElement(he,null))};t(103);!function(){var e=document.getElementsByTagName("html")[0],n=function(){e.style.fontSize=Math.min(document.body.clientWidth/7.5,100)+"px"};window.addEventListener("resize",n,!1),n()}(),i.a.render(r.a.createElement(r.a.StrictMode,null,r.a.createElement(_n,null)),document.getElementById("root"))},54:function(e,n,t){e.exports=t(104)},74:function(e,n,t){},80:function(e,n,t){}},[[54,1,2]]]);