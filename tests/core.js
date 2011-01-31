/**
 * Unit test for haneWIN OpenPGP implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @todo    Use JsUnit
 */

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
  var Ausdruck = new RegExp("SK-"+type+":(.+)");
  Ausdruck.exec(info);
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
