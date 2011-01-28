/**
 * Unit test for gpgmobile implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @todo    Use JsUnit
 */

/* test data ---------------------------------------------------------------- */
var key_sec = ReadFile("test.gpg.secret.asc");
var key_pub = ReadFile("test.gpg.public.asc");
document.getElementById("key_sec").innerHTML = key_sec;
document.getElementById("key_pub").innerHTML = key_pub;
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
var exp_text = "a test string\r\n";
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
var text_enc = gpgEncrypt(key_pub, exp_text);
Expect("Encrypted text",
       "-----BEGIN PGP MESSAGE-----",
       text_enc.split(["\n"])[0]);
document.getElementById("text_enc").innerHTML = text_enc;
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
var text_plain = gpgDecrypt(key_sec, text_enc);
Expect("Decrypted text",
       exp_text,
       text_plain);
document.getElementById("text_plain").innerHTML = text_plain;
/* -------------------------------------------------------------------------- */
