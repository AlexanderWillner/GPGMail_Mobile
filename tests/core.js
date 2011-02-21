/**
 * Unit test for haneWIN OpenPGP implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @todo    Use JsUnit
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
    // branch for native XMLHttpRequest object
    if (window.XMLHttpRequest) {
        req = new XMLHttpRequest();
        req.open("GET", fileUrl, false);
        req.send(null);
        fileContent = req.responseText;
    // branch for IE/Windows ActiveX version
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

function Expect(descr, expected, result) {
    if (expected == result) {
        pf = "<span class='pass'>PASS</span>";
    } else {
        pf = "<span class='fail'>FAIL</span><div class='info'>(expected: '" + expected + "', was: '"+result+"')</div>";
    }
    item = document.createElement('li');
    item.innerHTML = "Result for '" + descr + "': " + pf;
    document.getElementById("results").appendChild(item);
}

function ExpectTrue(descr, bool) {
    if (bool == true) {
        pf = "<span class='pass'>PASS</span>";
    } else {
        pf = "<span class='fail'>FAIL</span><div class='info'>(expected: '" + bool + "', was: '"+ !bool +"')</div>";
    }
    item = document.createElement('li');
    item.innerHTML = "Result for '" + descr + "': " + pf;
    document.getElementById("results").appendChild(item);
}
