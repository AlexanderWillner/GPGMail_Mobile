function gpgEncrypt(pubkey, message) {
    var pu=new getPublicKey(pubkey);
    var key = pu.pkey.replace(/\n/g,'');
    var id = pu.keyid;
    var type = 0; // RSA
    return doEncrypt(id, type, key, message);
}

function gpgDecrypt(seckey, message) {
    var result = doDecrypt([], [], [], [], seckey);
    var u = GetKeyValue(result, "u").split(",");
    var d = GetKeyValue(result, "d").split(",");
    var p = GetKeyValue(result, "p").split(",");
    var q = GetKeyValue(result, "q").split(",");
    return doDecrypt(p, q, d, u, message);
}

function gpgEncryptFromIdentifier(identifier, message) {
    var pubkey = ReadFile("http://pgp.mit.edu:11371/pks/lookup?op=get&search="
                          + identifier).split("\r\n");
    var token = 0;
    var result = "";
    for (var i = 0; i < pubkey.length; i++) {
        if (token == 0 && pubkey[i] != "-----BEGIN PGP PUBLIC KEY BLOCK-----")
            continue;
        token = 1;
        result += pubkey[i] + "\r\n";
        if (pubkey[i] == "-----END PGP PUBLIC KEY BLOCK-----")
            break;
    }
    return gpgEncrypt(pubkey, message);
}
