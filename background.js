"use strict";console.log("background script started");let CTC={notifications:[]};const CONTEXT_MENU_ID="MY_CONTEXT_MENU";function contextMenuClick(e,n){console.log("context menu click",e,n,e.selectionText),console.log("Dial phone from context menu: ",e.selectionText,e.selectionText.replace(/\D/g,"")),dialPhone(e.selectionText)}function getServer(){return new Promise((e,n)=>{chrome.storage.local.get("settings",(function(t){void 0!==t.settings&&((t=t.settings).server?e(t.server):n("Settings Server not found"))}))})}function findFop2Tab(e){return new Promise((n,t)=>{chrome.tabs.query({},(function(o){o.forEach((function(t){t.url.includes(e)&&n(t)})),t("FOP2 tab was not found")}))})}async function dialPhone(e){e=e.replace(/\D/g,"");let n=await getServer(),t=await findFop2Tab(n);chrome.tabs.get(t.id,(function(n){chrome.tabs.executeScript(n.id,{code:'console.log("External dial: ", '+e+");location.href=\"javascript:dial('"+e+"');\""})}))}function clearOldNotifications(){console.log("Clear Notifications:",CTC.notifications),CTC.notifications.forEach((function(e){chrome.notifications.clear(e,(function(e){console.log("Notification Removed",e)}))}))}async function incomingCall(e){clearOldNotifications();let n=null,t="Incoming phone call:";e.phoneNumber&&(t=t+"\n"+e.phoneNumber),e.phoneName&&(t=t+"\n"+e.phoneName),chrome.notifications.create("",{requireInteraction:!0,type:"basic",iconUrl:"/assets/img/tel-128.png",title:"Incoming Call",message:t,contextMessage:"Click to call",buttons:[{title:"Answer",iconUrl:"/assets/img/tel-128-green.png"},{title:"Disconnect",iconUrl:"/assets/img/tel-128-red.png"}]},(function(e){n=e,CTC.notifications.push(e)})),chrome.notifications.onButtonClicked.addListener((function(e,n){e==e&&(0===n?callAnswered():1===n&&callDisconnected())}))}async function callAnswered(){console.log("Answered");let e=await getServer(),n=await findFop2Tab(e);chrome.tabs.get(n.id,(function(e){chrome.tabs.update(e.id,{active:!0,highlighted:!0}),chrome.tabs.executeScript(e.id,{code:"console.log(\"External command: Answered\");location.href=\"javascript:document.querySelector('#phoneiframe').contentWindow.document.querySelector('#call').click();\""})}))}async function callDisconnected(){console.log("Disconnected");let e=await getServer(),n=await findFop2Tab(e);chrome.tabs.get(n.id,(function(e){chrome.tabs.update(e.id,{active:!0,highlighted:!0}),chrome.tabs.executeScript(e.id,{code:"console.log(\"External command: Answered\");location.href=\"javascript:document.querySelector('#phoneiframe').contentWindow.document.querySelector('#hang').click();\""})}))}chrome.contextMenus.removeAll((function(){chrome.contextMenus.create({id:CONTEXT_MENU_ID,title:"Dial: '%s'",contexts:["selection"]})})),chrome.contextMenus.onClicked.addListener(contextMenuClick),chrome.runtime.onInstalled.addListener((function(){chrome.storage.local.clear(),chrome.storage.local.set({settings:{}},(function(){}))})),chrome.runtime.onMessage.addListener((async function(e,n,t){return console.log("content message:",e),e&&"dialPhone"==e.type&&(dialPhone(e.data),t("success")),e&&"incomingCall"==e.type&&(incomingCall(e.data),t("success")),e&&"clearOldNotifications"==e.type&&(clearOldNotifications(),t("success")),!0}));