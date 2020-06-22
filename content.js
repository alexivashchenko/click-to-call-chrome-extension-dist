/**
*
*  Base64 encode / decode
*  http://www.webtoolkit.info/
*
**/

var Base64 = {
 
    // private property
    _keyStr : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
 
    // public method for encoding
    encode : function (input) {
        var output = "";
        var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
        var i = 0;
 
        input = Base64._utf8_encode(input);
 
        while (i < input.length) {
 
            chr1 = input.charCodeAt(i++);
            chr2 = input.charCodeAt(i++);
            chr3 = input.charCodeAt(i++);
 
            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;
 
            if (isNaN(chr2)) {
                enc3 = enc4 = 64;
            } else if (isNaN(chr3)) {
                enc4 = 64;
            }
 
            output = output +
            this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) +
            this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
 
        }
 
        return output;
    },
 
    // public method for decoding
    decode : function (input) {
        var output = "";
        var chr1, chr2, chr3;
        var enc1, enc2, enc3, enc4;
        var i = 0;
 
        input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
 
        while (i < input.length) {
 
            enc1 = this._keyStr.indexOf(input.charAt(i++));
            enc2 = this._keyStr.indexOf(input.charAt(i++));
            enc3 = this._keyStr.indexOf(input.charAt(i++));
            enc4 = this._keyStr.indexOf(input.charAt(i++));
 
            chr1 = (enc1 << 2) | (enc2 >> 4);
            chr2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            chr3 = ((enc3 & 3) << 6) | enc4;
 
            output = output + String.fromCharCode(chr1);
 
            if (enc3 != 64) {
                output = output + String.fromCharCode(chr2);
            }
            if (enc4 != 64) {
                output = output + String.fromCharCode(chr3);
            }
 
        }
 
        output = Base64._utf8_decode(output);
 
        return output;
 
    },
 
    // private method for UTF-8 encoding
    _utf8_encode : function (string) {
        string = string.replace(/\r\n/g,"\n");
        var utftext = "";
 
        for (var n = 0; n < string.length; n++) {
 
            var c = string.charCodeAt(n);
 
            if (c < 128) {
                utftext += String.fromCharCode(c);
            }
            else if((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            }
            else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
 
        }
 
        return utftext;
    },
 
    // private method for UTF-8 decoding
    _utf8_decode : function (utftext) {
        var string = "";
        var i = 0;
        var c = c1 = c2 = 0;
 
        while ( i < utftext.length ) {
 
            c = utftext.charCodeAt(i);
 
            if (c < 128) {
                string += String.fromCharCode(c);
                i++;
            }
            else if((c > 191) && (c < 224)) {
                c2 = utftext.charCodeAt(i+1);
                string += String.fromCharCode(((c & 31) << 6) | (c2 & 63));
                i += 2;
            }
            else {
                c2 = utftext.charCodeAt(i+1);
                c3 = utftext.charCodeAt(i+2);
                string += String.fromCharCode(((c & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
                i += 3;
            }
 
        }
 
        return string;
    }
 
}

/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * chrsz));}
function b64_md5(s){ return binl2b64(core_md5(str2binl(s), s.length * chrsz));}
function str_md5(s){ return binl2str(core_md5(str2binl(s), s.length * chrsz));}
function hex_hmac_md5(key, data) { return binl2hex(core_hmac_md5(key, data)); }
function b64_hmac_md5(key, data) { return binl2b64(core_hmac_md5(key, data)); }
function str_hmac_md5(key, data) { return binl2str(core_hmac_md5(key, data)); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);

}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Calculate the HMAC-MD5, of a key and some data
 */
function core_hmac_md5(key, data)
{
  var bkey = str2binl(key);
  if(bkey.length > 16) bkey = core_md5(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_md5(ipad.concat(str2binl(data)), 512 + data.length * chrsz);
  return core_md5(opad.concat(hash), 512 + 128);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert a string to an array of little-endian words
 * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
 */
function str2binl(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (i%32);
  return bin;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (i % 32)) & mask);
  return str;
}

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of little-endian words to a base-64 string
 */
function binl2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * ( i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * ((i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * ((i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}





function inIframe() {
	try {
		return window.self !== window.top;
	} catch (e) {
		return true;
	}
}

// do not ru extension inside iframe
if (inIframe()) {

	console.log('Extension loaded inside iframe. Abort.');

} else {




	let CTC = {

		dev: true,
		phoneLinksInfo: false,

		showedNotification: false,
		startNotification: false,
		notificationOperator: false,

		notification: {},
		startCollectNotificationData: false,

		requiredSettings: [
			'ssl',
			'server',
			'port',
			'extension',
			'password'
		],

		settings: {},

		log: function (...arguments) {

			if (CTC.dev == false) {
				return false;
			}

			if (arguments.length > 0) {
				arguments.forEach((arg) => {
					console.log(arg);
				});
			}
		}
	};

	let _debug = false,
		ssl = true,
		ws = false,
		context = "",
		myposition = 1,
		secret = null,
		exten = null,
		lastkey = "",
		wshost = null,
		wsport = null,
		pingcount = 0,
		alreadynotified = 0,
		prefix = "",
		botonitos = [],
		activeCalls = [];


	function inArray(n, e) {
		return -1 !== e.indexOf(n)
	}


	function __debug(...arguments) {
		if (_debug == false) {
			return false;
		}

		if (arguments.length > 0) {
			arguments.forEach((arg) => {
				if (typeof arg == 'string' && !arg.includes('style=') && !arg.includes('ping=') && !arg.includes('pong=') && !arg.includes('plugin=')) {


					void 0 !== window.console && console.log(arg)
				}
			})
		}
	}



	function send(n) {

		if (typeof ws == 'undefined' || ws == false) {
			__debug('Error. WebSocked is undefined.', ws);
			return false;
		}
		if (!n.includes('|ping|')) {
			__debug("sending command " + n);
		}
		ws.send(n);
	}


	function sendsPing() {
		// return true;
		__debug("ping " + pingcount), 5 < pingcount && __debug("Connection problem with websocket server!"), send('<msg data="1|ping||" />'), pingcount++
	}

	function connectContext() {
		"" !== context ? send('<msg data="' + context.toUpperCase() + '|contexto|1|" />') : send('<msg data="GENERAL|contexto|1|" />');
		setTimeout((function () {
			sendsPing()
		}), 1e4)
	}

	function doCommand(btn, cmd, data, slot) {

		"status" == cmd && (cmd = "xstatus"),
			"zbuttons" != cmd && __debug(btn + "," + cmd + "=" + data + " en slot " + slot),
			"function" == typeof execute[cmd] && execute[cmd](btn, data, slot);

	}

	function appendData(response) {
		var btn = response.btn;

		1 <= btn.indexOf("@") && (btn = btn.substring(0, btn.indexOf("@"))),

			doCommand(btn, response.cmd, response.data, response.slot);
	}


	function responseReact(response) {

		let _response = response;

		if (_response.cmd && (_response.cmd == 'pong' || _response.cmd == 'idletimer' || _response.cmd == 'setidle')) {
			return false;
		}

		if (_response.cmd && (_response.cmd == 'queuemember' || _response.cmd == 'stats') && _response.data) {
			_response.data = JSON.parse(Base64.decode(_response.data));
		}
		if (_response.cmd && (
			_response.cmd == 'clidname'
			|| _response.cmd == 'clidnum'
			|| _response.cmd == 'plugin'
			|| _response.cmd == 'style'
			|| _response.cmd == 'restrictq'
			|| _response.cmd == 'permitbtn'
			|| _response.cmd == 'preferences'
			|| _response.cmd == 'defaultpreferences'
			|| _response.cmd == 'vmailpath'
			|| _response.cmd == 'zbuttons'
			|| _response.cmd == 'permit'
		) && _response.data) {
			_response.data = Base64.decode(_response.data);
		}

		CTC.log(_response);
	}




	function getOperatorId(data) {
		if (typeof data == 'string') {
			data = JSON.parse(Base64.decode(data));
		}
		let loc = data[0].loc;
		loc = loc.replace('Local/', '');
		loc = loc.replace('@from-queue/n', '');
		loc = parseInt(loc);
		// console.log('getOperatorId: ' + loc, data);
		return loc;
	}
	function getOperatorState(data) {
		if (typeof data == 'string') {
			data = JSON.parse(Base64.decode(data));
		}
		return data[0].state;
	}




	function _notification(response) {

		// run oly if FOP2 page
		if (!window.location.href.includes(CTC.settings.server)) {
			return false;
		}

		if (CTC.startCollectNotificationData === true) {

			// get incoming phone number
			if (response.cmd && response.cmd == 'clidnum' && response.data) {
					CTC.notification.phoneNumber = response.data;
			}

			// get incoming phone name
			if (response.cmd && response.cmd == 'clidname' && response.data) {
				CTC.notification.phoneName = response.data;
			}

			if (response.cmd && response.cmd == 'notifyringing' && response.data && response.data == 1) {

				// stop collect data for notification
				CTC.startCollectNotificationData = false;

				// send notification
				runBackgroundCommand('incomingCall', CTC.notification);

			}

		}




		if (response.cmd && response.cmd == 'queuemember' && response.data) {

			CTC.notificationOperator = getOperatorId(response.data);

			// if current operator
			if (CTC.notificationOperator == CTC.settings.extension) {

				if (getOperatorState(response.data) == 'ringing') {

					// start collect data for notification
					CTC.startCollectNotificationData = true;

				} else {

					CTC.notification = {};

					runBackgroundCommand('clearOldNotifications', null);
				}

			}

		}


	}





	function defineWebSocketUrl() {

		let protocol = 'ws';

		if (CTC.settings.ssl == 'true') {

			protocol = 'wss'
		}

		return protocol + '://' + CTC.settings.server + ':' + CTC.settings.port;
	}


	function connectWebsocket() {

		if (ws !== false) {
			return false;
		}

		if ('WebSocket' in window) {

			let url = defineWebSocketUrl();

			CTC.log('Start WebSocket connection: ' + url);

			try {
				ws = new WebSocket(url)
			} catch (Error) {
				CTC.log('WebSocket error', Error);
			}

			ws.onopen = function () {
				connectContext();
			}

			ws.onmessage = function (event) {

				let response = JSON.parse(event.data);

				appendData(response);

				responseReact(response);

				_notification(response);
			}

			ws.onclose = function () {

				setTimeout((function () {

					connectWebsocket();

				}), 5000);

				CTC.log('Unable to connect to server: ' + url);
				ws = false;
			}

			ws.onerror = function (Error) {
				__debug(Error)
				console.error(Error);
			}

		} else {
			console.error('Your browser does not support WebSocket connection');
		}
	}

	function stripNonNumeric(n) {
		n += "";
		for (var e = /^\d$/, t = "", r = 0; r < n.length; r++) e.test(n.charAt(r)) && ("." == n.charAt(r) && -1 != t.indexOf(".") || "-" == n.charAt(r) && 0 != t.length || (t += n.charAt(r)));
		return t
	}


	function commandCenter() {
		function n(n, e) {
			if (myposition == n) {
				var t = localStorage.poplink,
					r = localStorage.popbody;
				if (void 0 === t && (t = ""), void 0 === r && (r = ""), "" != t) {
					var o = /#\{[^\}]*\}/g,
						i = t.match(o);
					if (null !== i)
						for (var a = 0; a < i.length; a++) {
							var c = i[a].substr(2, i[a].length - 3);
							o = "", o = "CLIDNUM" == c || "CLIDNAME" == c ? Base64.decode(chanvars[n][c]) : chanvars[n][c], t = replace(t, i[a], o)
						}
				}
				if (typeof popup !== 'undefined' && 1 == popup) {
					translate("&" + e);
					if (void 0 !== chanvars[n])
						for (c in chanvars[n]) {
							if ("CLIDNUM" == c || "CLIDNAME" == c) value = Base64.decode(chanvars[n][c]);
							else if (/^[0-9]*$/.test(chanvars[n][c])) value = chanvars[n][c];
							else try {
								value = windows.atob(chanvars[n][c])
							} catch (e) {
								value = chanvars[n][c]
							}
							value + "\n"
						}
				}
			}
		}
		this.zbuttons = function (n, e, t) {
			for (botonitos = [], chanvars = [], __debug(e), 29 <= subversion ? e = Base64.decode(e).split("\n") : (n = new Inflator(new Base64Reader(e)), e = new TextReader(new Utf8Translator(n)).readToEnd().split("\n")), t = 0; t < e.length; t++) {
				var r = e[t].split("!"),
					o = r[0].split("@")[0];
				for (n = 0; n < r.length; n++) {
					var i = r[n].split("=", 2);
					null == botonitos[o] && (botonitos[o] = {}), botonitos[o][i[0]] = i[1], "" !== i[0] && "EXTENSION" == i[0] && i[1] == exten && (myposition = o, __debug("My position is " + myposition))
				}
			}
		}, this.voicemail = function (n, e, t) {
			return !1
		}, this.pong = function (n, e, t) {
			setTimeout((function () {
				sendsPing()
			}), 2e4), pingcount--
		}, this.state = function (n, e, t) {
			if (0 <= inArray("RINGING", e = e.split("+")) || 0 <= inArray("UP", e)) "free", e = "busy";
			else if ("busy", e = "free", myposition == n && (alreadynotified = 0, void 0 !== chanvars[n]))
				for (var r in chanvars[n]) delete chanvars[n][r]
		}, this.presence = function (n, e, t) { }, this.key = function (n, e, t) {
			lastkey = e, __debug("lastkey: " + lastkey)
		}, this.setvar = function (n, e, t) {
			myposition == n && (1 <= (e = Base64.decode(e)).indexOf("=") && (void 0 === chanvars[n] && (chanvars[n] = {}),
				partes = e.split("="), chanvars[n][partes[0]] = partes[1]))
		}, this.incorrect = function (n, e, t) {
			__debug("Auth incorrect")
		}, this.version = function (n, e, t) {
			n = hex_md5(secret + lastkey), subversion = e.split("!")[0].split(".")[1],
				subversion = subversion.replace(/\D/g, ""),
				send('<msg data="1|auth|' + exten + "|" + n + '" />')
		}, this.qualify = function (n, e, t) {
			return !1
		}, this.clidnum = function (n, e, t) {
			myposition == n && (void 0 === chanvars[n] && (chanvars[n] = {}), chanvars[n].CLIDNUM = e)
		}, this.clidname = function (n, e, t) {
			myposition == n && (void 0 === chanvars[n] && (chanvars[n] = {}), chanvars[n].CLIDNAME = e)
		}, this.fromqueue = function (n, e, t) {
			myposition == n && (void 0 === chanvars[n] && (chanvars[n] = {}), chanvars[n].FROMQUEUE = e)
		}, this.notifyringing = function (e, t, r) {
			n(e, "incoming_call")
		}, this.notifyconnect = function (e, t, r) {
			0 == alreadynotified && (n(e, "connected_call"), myposition == e && (alreadynotified = 1))
		}
	}
	var execute = new commandCenter;




	function phoneClickEventListener(e) {

		e.preventDefault();

		let phone = e.currentTarget.href.replace("callto:", "").replace("tel:", "");

		runBackgroundCommand('dialPhone', phone);
	}


	function addPhoneLinks(phoneLinks) {
		phoneLinks.forEach(phoneLink => {
			phoneLink.removeEventListener('click', phoneClickEventListener);
			phoneLink.addEventListener('click', phoneClickEventListener);
		});
	}



	function runBackgroundCommand(Command, Data) {


		CTC.log('runBackgroundCommand start: ' + Command, Data);

		let EVENT_REPLY = '__rw_chrome_ext_reply_' + new Date().getTime();

		chrome.runtime.sendMessage({
			type: Command,
			data: Data
		}, function (data) {

			if (typeof chrome.runtime.lastError !== 'undefined') {

				if (typeof chrome.runtime.lastError.message !== 'undefined') {
					CTC.log('chrome.runtime.lastError.message for: ' + Command, data, chrome.runtime.lastError.message);
				} else {
					CTC.log('chrome.runtime.lastError.message for: ' + Command, data, chrome.runtime.lastError);
				}

			}

			var event = document.createEvent('Events');

			event.initEvent(EVENT_REPLY, false, false);

			CTC.log('runBackgroundCommand end: ' + Command, data);



		});

	}











	function getSettings() {
		return new Promise((resolve, reject) => {

			chrome.storage.local.get('settings', function (settings) {

				settings = settings.settings;

				let undefinedSettings = [];

				CTC.requiredSettings.forEach(function (field) {

					if (typeof settings[field] == 'undefined') {

						undefinedSettings.push(field);
					}
				});

				if (undefinedSettings.length == 0) {

					resolve(settings);

				} else {

					reject({
						type: 'error',
						content: 'Settings is undefined',
						data: undefinedSettings
					});

				}

			});
		});
	}


	function setUpWebSockedSettings() {
		ssl = CTC.settings.ssl;
		wshost = CTC.settings.server;
		wsport = CTC.settings.port;
		exten = CTC.settings.extension;
		secret = CTC.settings.password;
	}


	function ifFop2Page() {
		if (CTC.settings.server && window.location.href.includes(CTC.settings.server)) {
			return true;
		}
		return false;
	}

	function proceedPhoneLinks() {

		let phoneLinksFound = false;

		// if the page is FOP2 - start WebSocket anyway
		if (ifFop2Page()) {
			connectWebsocket();
		}

		setInterval(() => {

			let phoneLinks = document.querySelectorAll('a.click-to-call[href*="callto"], a.click-to-call[href*="tel"]');

			if (phoneLinks.length > 0) {

				if (CTC.phoneLinksInfo) {
					CTC.log('Phone links founded: ' + phoneLinks.length);
				}

				if (phoneLinksFound === false && !ifFop2Page()) {

					connectWebsocket();
				}

				addPhoneLinks(phoneLinks);

				phoneLinksFound = true;

			} else {
				if (phoneLinksFound === false) {

					if (CTC.phoneLinksInfo) {
						CTC.log('Phone links not found...');
					}
				}
			}

		}, 2000);
	}


	async function init() {

		CTC.settings = await getSettings();

		CTC.log('CTC.settings', CTC.settings);

		setUpWebSockedSettings();

		proceedPhoneLinks();

	}


	window.addEventListener('load', () => {

		init();

	}, false);


}