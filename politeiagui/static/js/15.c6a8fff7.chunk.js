(window.webpackJsonp=window.webpackJsonp||[]).push([[15],{1278:function(e,a,t){"use strict";t.r(a);var n=t(0),r=t.n(n),l=t(162),i=t.n(l),c=t(568),s=t(339),o=t(132),m=t(330),u=t(27),d=function(e){var a=e.items;return Array.isArray(a)?r.a.createElement("ul",null,a.map(function(e,a){return r.a.createElement("li",{key:a,style:{padding:"3px 0px"}},e)})):a instanceof Error?a.message:a},p=t(51),E=t(565),f=t(550),v=t(54),b=t(23),g=function(e){return r.a.createElement(c.a,{input:e.input,toggledStyle:!0})};a.default=function(e){var a=e.isLoading,t=e.PageLoadingIcon,n=e.policy,l=e.error,c=e.warning,h=e.onSave,y=e.onSaveProposalDraft,N=e.submitting,x=e.handleSubmit,w=e.validationError,C=e.submitError,k=e.userCanExecuteActions,j=e.openModal,O=e.proposalCredits,A=e.loggedInAsEmail,M=e.editingMode,S=e.isDraftSaving,I=e.draftButtonText,z=A&&!N&&!l&&!w&&k&&(O>0||M);return!n||a?r.a.createElement(t,null):r.a.createElement("div",{className:"content",role:"main"},r.a.createElement("div",{className:"page submit-proposal-page"},r.a.createElement(i.a,{className:"submit-page"}),r.a.createElement("div",{className:"submit conztent warn-on-unload",id:"newlink"},w&&r.a.createElement(u.a,{type:"error",header:"Error creating proposal"},r.a.createElement(d,{items:w})),!l&&c&&r.a.createElement(u.a,{type:"warn",header:"Warning"},r.a.createElement(d,{items:c})),r.a.createElement("div",{className:"formtabs-content"},r.a.createElement("div",{className:"spacer"},r.a.createElement(E.a,{name:"global",component:function(e){return r.a.createElement(o.a,Object.assign({title:"Cannot submit proposal"},e))}}),r.a.createElement("div",{className:"roundfield",id:"title-field"},r.a.createElement("div",{className:"roundfield-content"},r.a.createElement("div",{style:{display:"flex",width:"100%"}},r.a.createElement(E.a,{name:"name",component:m.a,tabIndex:1,type:"text",placeholder:"Proposal Name"}),M?r.a.createElement("div",{style:{flex:"1",display:"flex",justifyContent:"flex-end"}},r.a.createElement("span",{style:{color:"#777"}},r.a.createElement("i",{className:"fa fa-edit right-margin-5"}),"Editing")):null),r.a.createElement("input",{name:"kind",type:"hidden",defaultValue:"self"}),r.a.createElement("div",{className:"usertext"},r.a.createElement("input",{name:"thing_id",type:"hidden",defaultValue:!0}),r.a.createElement("div",{className:"usertext-edit md-container",style:{}},r.a.createElement("div",{className:"md"},r.a.createElement(E.a,{name:"description",component:g,tabIndex:2,placeholder:"Markdown Entry",rows:20,cols:80}),r.a.createElement("a",{target:"_blank",rel:"noopener noreferrer",href:b.Z,style:{fontSize:"1.01em"}},"Learn how to format your proposal"),r.a.createElement(E.a,{name:"files",className:"attach-button greenprimary",component:s.a,userCanExecuteActions:k,placeholder:"Attach a file",policy:n,normalize:s.b})))),r.a.createElement("div",{className:"submit-wrapper"},r.a.createElement("button",{className:"togglebutton access-required".concat(!z&&" not-active disabled"),name:"submit",type:"submit",value:"form",onClick:x(h)},M?"update":"submit"),r.a.createElement(p.a,{className:"togglebutton secondary access-required",name:"submit",type:"submit",value:"form",text:I,onClick:x(y),isLoading:S}),0===O&&!M&&r.a.createElement("div",{className:"submit-button-error"},"To submit a proposal, you must purchase a proposal credit.",r.a.createElement("span",{className:"linkish",onClick:function(){return j(v.h)}}," ","Click here")," ","to open the proposal credits manager."),r.a.createElement("p",{style:{fontSize:"16px",display:"flex",paddingTop:"1em"}},r.a.createElement("b",null,"NOTE:\xa0")," Drafts are locally stored in the browser and will NOT be available across different browsers or devices.")),C?r.a.createElement(u.a,{type:"error",header:"Error ".concat(M?"updating":"creating"," proposal"),body:C}):null))),r.a.createElement("div",{className:"spacer"},r.a.createElement("div",{className:"roundfield"},r.a.createElement(f.a,null)))))))}},328:function(e,a){e.exports=function(e){return void 0===e}},329:function(e,a,t){var n=t(139),r=t(147),l=t(84),i=t(37);e.exports=function(){var e=arguments.length;if(!e)return[];for(var a=Array(e-1),t=arguments[0],c=e;c--;)a[c-1]=arguments[c];return n(i(t)?l(t):[t],r(a,1))}},330:function(e,a,t){"use strict";var n=t(0),r=t.n(n);a.a=function(e){var a=e.input,t=e.label,n=e.placeholder,l=e.tabIndex,i=e.type,c=e.meta,s=c.touched,o=c.error,m=c.warning;return r.a.createElement("div",{className:"input-with-error"},r.a.createElement("label",null,t),r.a.createElement("input",Object.assign({},a,{tabIndex:l,placeholder:n,type:i})),r.a.createElement("div",{className:"input-subline"},s&&(o&&r.a.createElement("div",{className:"input-error"},o)||m&&r.a.createElement("div",{className:"input-warning"},m))))}},339:function(e,a,t){"use strict";var n=t(12),r=t(13),l=t(15),i=t(14),c=t(16),s=t(0),o=t.n(s),m=t(105),u=t.n(m),d=t(26),p=t(169),E=t(27),f=function(e){var a=e.errors;return o.a.createElement("div",null,a.map(function(e,a){return o.a.createElement(E.a,{key:a,body:e,type:"error"})}))},v=t(322),b=t(37),g=t.n(b),h=t(328),y=t.n(h),N=t(329),x=t.n(N),w=t(195),C=t.n(w);t.d(a,"a",function(){return k}),t.d(a,"b",function(){return j});var k=function(e){function a(e){var t;return Object(n.a)(this,a),(t=Object(l.a)(this,Object(i.a)(a).call(this,e))).handleFilesChange=function(e){var a=t.props,n=a.input,r=a.meta.dispatch,l=a.policy,i=Object(v.a)(e),c=n.value?i.concat(n.value):i,s=Object(v.c)(c,l),o=s.errors,m=s.files;return t.setState({policyErrors:o||[]}),s.errors.length>0?m.length>0?r(Object(d.a)("form/record","files",m)):void 0:r(Object(d.a)("form/record","files",c))},t.state={policyErrors:[]},t}return Object(c.a)(a,e),Object(r.a)(a,[{key:"render",value:function(){var e=this.props,a=e.placeholder,t=void 0===a?"Upload":a,n=e.input,r=e.touched,l=e.error,i=e.disabled,c=e.policy,s=e.userCanExecuteActions,m=this.state.policyErrors;return c&&o.a.createElement("div",{className:"attach-wrapper"},m.length>0&&o.a.createElement(f,{errors:m}),o.a.createElement("div",null,o.a.createElement(u.a,{base64:!0,multipleFiles:!0,fileTypes:c.validmimetypes,handleFiles:this.handleFilesChange},o.a.createElement("div",{className:"button-wrapper"},o.a.createElement("button",{className:"togglebutton access-required".concat(s?"":" not-active disabled"),style:{margin:0}},t),o.a.createElement("div",{className:"attach-requirements"},o.a.createElement("div",null," ","Max number of files: ",o.a.createElement("span",null,c.maximages,".")," "),o.a.createElement("div",null," ","Max file size:"," ",o.a.createElement("span",null,Math.floor(c.maximagesize/1024)," Kb."," ")," "),o.a.createElement("div",null," ","Valid MIME types:"," ",o.a.createElement("span",null,c.validmimetypes.join(", "))," "))))),r&&l&&!i&&o.a.createElement("span",{className:"error"},l),o.a.createElement(p.a,{files:n.value||[],onChange:n.onChange}))}}]),a}(o.a.Component),j=function(e,a){var t=[];return a&&g()(a)&&(t=C()(a)),y()(e.remove)||t.splice(e.remove,1),g()(e)&&(t=x()(t,e)),t}}}]);
//# sourceMappingURL=15.c6a8fff7.chunk.js.map