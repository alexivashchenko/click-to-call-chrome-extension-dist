var Base64={_keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(n){var e,t,r,o,i,a,d,s="",c=0;for(n=Base64._utf8_encode(n);c<n.length;)o=(e=n.charCodeAt(c++))>>2,i=(3&e)<<4|(t=n.charCodeAt(c++))>>4,a=(15&t)<<2|(r=n.charCodeAt(c++))>>6,d=63&r,isNaN(t)?a=d=64:isNaN(r)&&(d=64),s=s+this._keyStr.charAt(o)+this._keyStr.charAt(i)+this._keyStr.charAt(a)+this._keyStr.charAt(d);return s},decode:function(n){var e,t,r,o,i,a,d="",s=0;for(n=n.replace(/[^A-Za-z0-9\+\/\=]/g,"");s<n.length;)e=this._keyStr.indexOf(n.charAt(s++))<<2|(o=this._keyStr.indexOf(n.charAt(s++)))>>4,t=(15&o)<<4|(i=this._keyStr.indexOf(n.charAt(s++)))>>2,r=(3&i)<<6|(a=this._keyStr.indexOf(n.charAt(s++))),d+=String.fromCharCode(e),64!=i&&(d+=String.fromCharCode(t)),64!=a&&(d+=String.fromCharCode(r));return d=Base64._utf8_decode(d)},_utf8_encode:function(n){n=n.replace(/\r\n/g,"\n");for(var e="",t=0;t<n.length;t++){var r=n.charCodeAt(t);r<128?e+=String.fromCharCode(r):r>127&&r<2048?(e+=String.fromCharCode(r>>6|192),e+=String.fromCharCode(63&r|128)):(e+=String.fromCharCode(r>>12|224),e+=String.fromCharCode(r>>6&63|128),e+=String.fromCharCode(63&r|128))}return e},_utf8_decode:function(n){for(var e="",t=0,r=c1=c2=0;t<n.length;)(r=n.charCodeAt(t))<128?(e+=String.fromCharCode(r),t++):r>191&&r<224?(c2=n.charCodeAt(t+1),e+=String.fromCharCode((31&r)<<6|63&c2),t+=2):(c2=n.charCodeAt(t+1),c3=n.charCodeAt(t+2),e+=String.fromCharCode((15&r)<<12|(63&c2)<<6|63&c3),t+=3);return e}},hexcase=0,b64pad="",chrsz=8;function hex_md5(n){return binl2hex(core_md5(str2binl(n),n.length*chrsz))}function b64_md5(n){return binl2b64(core_md5(str2binl(n),n.length*chrsz))}function str_md5(n){return binl2str(core_md5(str2binl(n),n.length*chrsz))}function hex_hmac_md5(n,e){return binl2hex(core_hmac_md5(n,e))}function b64_hmac_md5(n,e){return binl2b64(core_hmac_md5(n,e))}function str_hmac_md5(n,e){return binl2str(core_hmac_md5(n,e))}function md5_vm_test(){return"900150983cd24fb0d6963f7d28e17f72"==hex_md5("abc")}function core_md5(n,e){n[e>>5]|=128<<e%32,n[14+(e+64>>>9<<4)]=e;for(var t=1732584193,r=-271733879,o=-1732584194,i=271733878,a=0;a<n.length;a+=16){var d=t,s=r,c=o,f=i;t=md5_ff(t,r,o,i,n[a+0],7,-680876936),i=md5_ff(i,t,r,o,n[a+1],12,-389564586),o=md5_ff(o,i,t,r,n[a+2],17,606105819),r=md5_ff(r,o,i,t,n[a+3],22,-1044525330),t=md5_ff(t,r,o,i,n[a+4],7,-176418897),i=md5_ff(i,t,r,o,n[a+5],12,1200080426),o=md5_ff(o,i,t,r,n[a+6],17,-1473231341),r=md5_ff(r,o,i,t,n[a+7],22,-45705983),t=md5_ff(t,r,o,i,n[a+8],7,1770035416),i=md5_ff(i,t,r,o,n[a+9],12,-1958414417),o=md5_ff(o,i,t,r,n[a+10],17,-42063),r=md5_ff(r,o,i,t,n[a+11],22,-1990404162),t=md5_ff(t,r,o,i,n[a+12],7,1804603682),i=md5_ff(i,t,r,o,n[a+13],12,-40341101),o=md5_ff(o,i,t,r,n[a+14],17,-1502002290),t=md5_gg(t,r=md5_ff(r,o,i,t,n[a+15],22,1236535329),o,i,n[a+1],5,-165796510),i=md5_gg(i,t,r,o,n[a+6],9,-1069501632),o=md5_gg(o,i,t,r,n[a+11],14,643717713),r=md5_gg(r,o,i,t,n[a+0],20,-373897302),t=md5_gg(t,r,o,i,n[a+5],5,-701558691),i=md5_gg(i,t,r,o,n[a+10],9,38016083),o=md5_gg(o,i,t,r,n[a+15],14,-660478335),r=md5_gg(r,o,i,t,n[a+4],20,-405537848),t=md5_gg(t,r,o,i,n[a+9],5,568446438),i=md5_gg(i,t,r,o,n[a+14],9,-1019803690),o=md5_gg(o,i,t,r,n[a+3],14,-187363961),r=md5_gg(r,o,i,t,n[a+8],20,1163531501),t=md5_gg(t,r,o,i,n[a+13],5,-1444681467),i=md5_gg(i,t,r,o,n[a+2],9,-51403784),o=md5_gg(o,i,t,r,n[a+7],14,1735328473),t=md5_hh(t,r=md5_gg(r,o,i,t,n[a+12],20,-1926607734),o,i,n[a+5],4,-378558),i=md5_hh(i,t,r,o,n[a+8],11,-2022574463),o=md5_hh(o,i,t,r,n[a+11],16,1839030562),r=md5_hh(r,o,i,t,n[a+14],23,-35309556),t=md5_hh(t,r,o,i,n[a+1],4,-1530992060),i=md5_hh(i,t,r,o,n[a+4],11,1272893353),o=md5_hh(o,i,t,r,n[a+7],16,-155497632),r=md5_hh(r,o,i,t,n[a+10],23,-1094730640),t=md5_hh(t,r,o,i,n[a+13],4,681279174),i=md5_hh(i,t,r,o,n[a+0],11,-358537222),o=md5_hh(o,i,t,r,n[a+3],16,-722521979),r=md5_hh(r,o,i,t,n[a+6],23,76029189),t=md5_hh(t,r,o,i,n[a+9],4,-640364487),i=md5_hh(i,t,r,o,n[a+12],11,-421815835),o=md5_hh(o,i,t,r,n[a+15],16,530742520),t=md5_ii(t,r=md5_hh(r,o,i,t,n[a+2],23,-995338651),o,i,n[a+0],6,-198630844),i=md5_ii(i,t,r,o,n[a+7],10,1126891415),o=md5_ii(o,i,t,r,n[a+14],15,-1416354905),r=md5_ii(r,o,i,t,n[a+5],21,-57434055),t=md5_ii(t,r,o,i,n[a+12],6,1700485571),i=md5_ii(i,t,r,o,n[a+3],10,-1894986606),o=md5_ii(o,i,t,r,n[a+10],15,-1051523),r=md5_ii(r,o,i,t,n[a+1],21,-2054922799),t=md5_ii(t,r,o,i,n[a+8],6,1873313359),i=md5_ii(i,t,r,o,n[a+15],10,-30611744),o=md5_ii(o,i,t,r,n[a+6],15,-1560198380),r=md5_ii(r,o,i,t,n[a+13],21,1309151649),t=md5_ii(t,r,o,i,n[a+4],6,-145523070),i=md5_ii(i,t,r,o,n[a+11],10,-1120210379),o=md5_ii(o,i,t,r,n[a+2],15,718787259),r=md5_ii(r,o,i,t,n[a+9],21,-343485551),t=safe_add(t,d),r=safe_add(r,s),o=safe_add(o,c),i=safe_add(i,f)}return Array(t,r,o,i)}function md5_cmn(n,e,t,r,o,i){return safe_add(bit_rol(safe_add(safe_add(e,n),safe_add(r,i)),o),t)}function md5_ff(n,e,t,r,o,i,a){return md5_cmn(e&t|~e&r,n,e,o,i,a)}function md5_gg(n,e,t,r,o,i,a){return md5_cmn(e&r|t&~r,n,e,o,i,a)}function md5_hh(n,e,t,r,o,i,a){return md5_cmn(e^t^r,n,e,o,i,a)}function md5_ii(n,e,t,r,o,i,a){return md5_cmn(t^(e|~r),n,e,o,i,a)}function core_hmac_md5(n,e){var t=str2binl(n);t.length>16&&(t=core_md5(t,n.length*chrsz));for(var r=Array(16),o=Array(16),i=0;i<16;i++)r[i]=909522486^t[i],o[i]=1549556828^t[i];var a=core_md5(r.concat(str2binl(e)),512+e.length*chrsz);return core_md5(o.concat(a),640)}function safe_add(n,e){var t=(65535&n)+(65535&e);return(n>>16)+(e>>16)+(t>>16)<<16|65535&t}function bit_rol(n,e){return n<<e|n>>>32-e}function str2binl(n){for(var e=Array(),t=(1<<chrsz)-1,r=0;r<n.length*chrsz;r+=chrsz)e[r>>5]|=(n.charCodeAt(r/chrsz)&t)<<r%32;return e}function binl2str(n){for(var e="",t=(1<<chrsz)-1,r=0;r<32*n.length;r+=chrsz)e+=String.fromCharCode(n[r>>5]>>>r%32&t);return e}function binl2hex(n){for(var e=hexcase?"0123456789ABCDEF":"0123456789abcdef",t="",r=0;r<4*n.length;r++)t+=e.charAt(n[r>>2]>>r%4*8+4&15)+e.charAt(n[r>>2]>>r%4*8&15);return t}function binl2b64(n){for(var e="",t=0;t<4*n.length;t+=3)for(var r=(n[t>>2]>>t%4*8&255)<<16|(n[t+1>>2]>>(t+1)%4*8&255)<<8|n[t+2>>2]>>(t+2)%4*8&255,o=0;o<4;o++)8*t+6*o>32*n.length?e+=b64pad:e+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(r>>6*(3-o)&63);return e}let _debug=!0,ssl=!0,ws=!1,context="",myposition=1,secret=null,exten=null,lastkey="",wshost=null,wsport=null,pingcount=0,alreadynotified=0,prefix="",botonitos=[];function inArray(n,e){return-1!==e.indexOf(n)}function debug(...arguments){if(0==_debug)return!1;arguments.length>0&&arguments.forEach(n=>{void 0!==window.console&&console.log(n)})}function send(n){if(void 0===ws||0==ws)return debug("Error. WebSocked is undefined.",ws),!1;debug("sending command "+n),ws.send(n)}function sendsPing(){debug("ping "+pingcount),5<pingcount&&debug("Connection problem with websocket server!"),send('<msg data="1|ping||" />'),pingcount++}function connectContext(){send(""!==context?'<msg data="'+context.toUpperCase()+'|contexto|1|" />':'<msg data="GENERAL|contexto|1|" />'),setTimeout((function(){sendsPing()}),1e4)}function doCommand(n,e,t,r){"status"==e&&(e="xstatus"),"zbuttons"!=e&&debug(n+","+e+"="+t+" en slot "+r),"function"==typeof execute[e]&&execute[e](n,t,r)}function appendData(n){var e=n.btn;1<=e.indexOf("@")&&(e=e.substring(0,e.indexOf("@"))),doCommand(e,n.cmd,n.data,n.slot)}function connectWebsocket(n){if(debug("connect xml to "+wshost+" at port "+wsport),"WebSocket"in window){let e="ws";"true"==ssl&&(e="wss"),n=e+"://"+wshost+":"+wsport;try{ws=new WebSocket(n)}catch(n){debug("web socket error")}ws.onopen=function(){connectContext()},ws.onmessage=function(n){appendData(n=JSON.parse(n.data))},ws.onclose=function(){setTimeout((function(){connectWebsocket()}),5e3),console.info("Unable to connect to server")},ws.onerror=function(n){debug(n)}}}function stripNonNumeric(n){n+="";for(var e=/^\d$/,t="",r=0;r<n.length;r++)e.test(n.charAt(r))&&("."==n.charAt(r)&&-1!=t.indexOf(".")||"-"==n.charAt(r)&&0!=t.length||(t+=n.charAt(r)));return t}function dial(n){if(n=stripNonNumeric(n),prefix=stripNonNumeric(prefix),0<n.length)if(0<myposition){var e=hex_md5(secret+lastkey);send('<msg data="'+myposition+"|dial|"+prefix+n+"|"+e+'" />')}else debug("unable to dial, no position defined");else debug("no dial as number is zero length")}function commandCenter(){function n(n,e){if(myposition==n){var t=localStorage.poplink,r=localStorage.popbody;if(void 0===t&&(t=""),void 0===r&&(r=""),""!=t){var o=/#\{[^\}]*\}/g,i=t.match(o);if(null!==i)for(var a=0;a<i.length;a++){var d=i[a].substr(2,i[a].length-3);o="",o="CLIDNUM"==d||"CLIDNAME"==d?Base64.decode(chanvars[n][d]):chanvars[n][d],t=replace(t,i[a],o)}}if(1==popup&&(translate("&"+e),void 0!==chanvars[n]))for(d in chanvars[n]){if("CLIDNUM"==d||"CLIDNAME"==d)value=Base64.decode(chanvars[n][d]);else if(/^[0-9]*$/.test(chanvars[n][d]))value=chanvars[n][d];else try{value=windows.atob(chanvars[n][d])}catch(e){value=chanvars[n][d]}value}}}this.zbuttons=function(n,e,t){for(botonitos=[],chanvars=[],debug(e),29<=subversion?e=Base64.decode(e).split("\n"):(n=new Inflator(new Base64Reader(e)),e=new TextReader(new Utf8Translator(n)).readToEnd().split("\n")),t=0;t<e.length;t++){var r=e[t].split("!"),o=r[0].split("@")[0];for(n=0;n<r.length;n++){var i=r[n].split("=",2);null==botonitos[o]&&(botonitos[o]={}),botonitos[o][i[0]]=i[1],""!==i[0]&&"EXTENSION"==i[0]&&i[1]==exten&&(myposition=o,debug("My position is "+myposition))}}},this.voicemail=function(n,e,t){return!1},this.pong=function(n,e,t){setTimeout((function(){sendsPing()}),2e4),pingcount--},this.state=function(n,e,t){if(0<=inArray("RINGING",e=e.split("+"))||0<=inArray("UP",e))e="busy";else if(e="free",myposition==n&&(alreadynotified=0,void 0!==chanvars[n]))for(var r in chanvars[n])delete chanvars[n][r]},this.presence=function(n,e,t){},this.key=function(n,e,t){lastkey=e,debug("lastkey: "+lastkey)},this.setvar=function(n,e,t){myposition==n&&1<=(e=Base64.decode(e)).indexOf("=")&&(void 0===chanvars[n]&&(chanvars[n]={}),partes=e.split("="),chanvars[n][partes[0]]=partes[1])},this.incorrect=function(n,e,t){debug("Auth incorrect")},this.version=function(n,e,t){n=hex_md5(secret+lastkey),subversion=e.split("!")[0].split(".")[1],subversion=subversion.replace(/\D/g,""),send('<msg data="1|auth|'+exten+"|"+n+'" />')},this.qualify=function(n,e,t){return!1},this.clidnum=function(n,e,t){myposition==n&&(void 0===chanvars[n]&&(chanvars[n]={}),chanvars[n].CLIDNUM=e)},this.clidname=function(n,e,t){myposition==n&&(void 0===chanvars[n]&&(chanvars[n]={}),chanvars[n].CLIDNAME=e)},this.fromqueue=function(n,e,t){myposition==n&&(void 0===chanvars[n]&&(chanvars[n]={}),chanvars[n].FROMQUEUE=e)},this.notifyringing=function(e,t,r){n(e,"incoming_call")},this.notifyconnect=function(e,t,r){0==alreadynotified&&(n(e,"connected_call"),myposition==e&&(alreadynotified=1))}}var execute=new commandCenter;window.addEventListener("load",()=>{chrome.storage.local.get("settings",(function(n){if(void 0!==n.settings&&(n=n.settings),debug("settings",n),void 0===n||void 0===n.ssl||void 0===n.server||void 0===n.port||void 0===n.extension||void 0===n.password)return console.info("Settings is undefined"),!1;ssl=n.ssl,wshost=n.server,wsport=n.port,exten=n.extension,secret=n.password,connectWebsocket();let e=document.querySelectorAll('a.click-to-call[href*="callto"], a.click-to-call[href*="tel"]');e.length>0&&e.forEach(n=>{n.addEventListener("click",n=>{n.preventDefault(),dial(n.currentTarget.href.replace("callto:","").replace("tel:",""))})})}))},!1);