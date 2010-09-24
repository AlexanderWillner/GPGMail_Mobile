/* Author: Herbert Hanewinkel */

var keytyp = 0;      // 0=RSA, 1=Elgamal
var keyid = '1234567890abcdef';
var pubkey = 'ABCDEFGHIJKLMNOPQRSTUVWXYZeu+pRVFP5tpboOlIwO2vqO/rCi8VvT2TPzEJarWhyZ465NIohYCiia9vaGUEp4rsDzFnVNgpON47yPew1zCmOOofituf+X6Qlaxylm5NnO4vnRcmoF4IbGwSCqyGgGor29D75Hovwlj1q6BWHYWwAGKQ==';

function load() {
 document.encrypt.pkey.value=pubkey;
 document.encrypt.keyid.value=keyid;
 if(keytyp == 0) document.encrypt.pktype.value='RSA';
 if(keytyp == 1) document.encrypt.pktype.value='ELGAMAL';
}

function encrypt() {
 pubkey=document.encrypt.pkey.value;

 if(document.encrypt.keyid.value.length) keyid=document.encrypt.keyid.value;
 else                              keyid='0000000000000000';
 if(keyid.length != 16)
 {
   alert('Invalid Key Id');
   return;
 } 
 
 keytyp = -1;
 if(document.encrypt.pktype.value == 'ELGAMAL') keytyp = 1;
 if(document.encrypt.pktype.value == 'RSA')     keytyp = 0;
 if(keytyp == -1)
 {
   alert('Unsupported Key Type');
   return;
 } 


 var startTime=new Date();

 var text=document.encrypt.text.value+'\r\n';
 document.encrypt.text.value=doEncrypt(keyid, keytyp, pubkey, text);

 var endTime=new Date();
 document.encrypt.howLong.value=(endTime.getTime()-startTime.getTime())/1000.0 + " ms";
}

function decrypt() {
    alert ("Not implemented yet");
}