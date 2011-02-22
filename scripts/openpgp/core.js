/**
 * Abstraction for the haneWIN OpenPGP implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @version 2011-02-22
 * @see     http://gpgtools.org
 * @license BSD
 * @todo    Implement more functionalities
 */

function OpenPGP_GetSecretInformation(key) {
    var result = new Array(4);
    var data = doDecrypt([], [], [], [], key);
    result['q'] = GetKeyValue(data, "q").split(",");
    result['p'] = GetKeyValue(data, "p").split(",");
    result['d'] = GetKeyValue(data, "d").split(",");
    result['u'] = GetKeyValue(data, "u").split(",");
    return result;
}

function OpenPGP_GetPublicInformation(key) {
    var result = new Array(2);
    var pu = new getPublicKey(key);

    result['mpi'] = pu.pkey.replace(/\n/g,'');
    result['id'] = pu.keyid;

    return result;
}

function OpenPGP_Decrypt(p, q, d, u, key) {
    return OpenPGP_ParseMessage(doDecrypt(p, q, d, u, key));
}

function OpenPGP_Encrypt(keyid, keytype, pubkey, exp_text) {
    return doEncrypt(keyid, keytype, pubkey, exp_text);
}

function OpenPGP_ParseMessage(message) {
    var regex = /---Start of literal data---\n([\s\S]*)\n---\n/
    regex.exec(message);
    return RegExp.$1;
}

function ReadFile(fileUrl) {
    var req;
    var fileContent;
    if (window.XMLHttpRequest) {
        req = new XMLHttpRequest();
        req.open("GET", fileUrl, false);
        req.send(null);
        fileContent = req.responseText;
    } else if (window.ActiveXObject) {
        req = new ActiveXObject("Microsoft.XMLHTTP");
        req.open("GET", fileUrl, false);
        req.onreadystatechange=function() {
                                    if (req.readyState == 4) {
                                        fileContent = req.responseText;
                                    }
                                }
        req.send(null);
    }
    return fileContent;
}

function GetKeyValue(info, type) {
  var regex = new RegExp("SK-"+type+":[0-9]+,(.+)");
  regex.exec(info);
  return(RegExp.$1);
}

