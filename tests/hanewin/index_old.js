/**
 * Unit test for haneWIN OpenPGP implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @todo    Use JsUnit
 */

/* test data ---------------------------------------------------------------- */
var key_sec = ReadFile("../data/test.gpg.secret.asc");
var key_pub = ReadFile("../data/test.gpg.public.asc");
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
var exp_u = "12075,254029157,49411353,118585420,30333430,182355735,113267204,59879655,246186742,89307457,122612671,87009111,182656057,146899134,253466372,74988166,102757214,66706255,113";
var exp_d = "16128693,257125582,198009612,139557212,137415092,28244646,262178813,164292477,91525038,156964779,247191904,267451101,228712303,53989207,261371544,246153944,150829682,249770095,25129227,261561015,81191918,43848397,16495765,53235668,162006057,193519501,106995674,95902518,126698399,218294843,33861852,240767243,89592116,130861474,79306072,77555856,3499";
var exp_p = "226197815,195655162,238712700,84661672,79309410,250904587,203484457,240974443,224227230,126874073,179538153,39985901,31019509,61544693,181895321,140514284,265995133,48022167,232";
var exp_q = "59391045,127440241,248887009,192654032,240088215,223902554,87919612,632607,82318265,127773417,126207976,43284671,118612664,11872646,165429592,27674223,243581030,191560393,249";
var exp_mpi = "BADiejt3X/biElrPwczuou+GxI1eVbbb0mAS5Eek0h8SKGBO9cHC/tj3uWG/bF6A2+q0WLj+46mI9j60drz5osu3aerjZkiZiGFj9GhdnvYZ7ErT+wV8koxj/2Lrbq8iQyfNpj76VqTl7Rl09BaR/eSm6o6mQ1clqqiEV0FOcTi30wARAQAB";
var exp_id = "a99b311c7f20062a";
var exp_text = "a test string\r\n";
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
document.getElementById("key_sec").innerHTML = key_sec;
document.getElementById("key_pub").innerHTML = key_pub;
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
var result = doDecrypt([], [], [], [], key_sec);
var result_u = GetKeyValue(result, "u");
var result_d = GetKeyValue(result, "d");
var result_p = GetKeyValue(result, "p");
var result_q = GetKeyValue(result, "q");
Expect("Secret u", exp_u, result_u);
Expect("Secret d", exp_d, result_d);
Expect("Secret p", exp_p, result_p);
Expect("Secret q", exp_q, result_q);

var pu=new getPublicKey(key_pub);
var pubkey = pu.pkey.replace(/\n/g,'');
var keyid = pu.keyid;
Expect("Public MPIs", exp_mpi, pubkey);
Expect("Public ID", exp_id, keyid);

var keytype = 0; // 0=RSA, 1=Elgamal
var text_enc = doEncrypt(keyid,
                         keytype,
                         pubkey,
                         exp_text);
Expect("Encrypted text",
       "-----BEGIN PGP MESSAGE-----",
       text_enc.split(["\n"])[0]);
document.getElementById("text_enc").innerHTML = text_enc;

var text_plain = doDecrypt(result_p.split(","),
                           result_q.split(","),
                           result_d.split(","),
                           result_u.split(","),
                           text_enc);
text_plain = GetMessageValue(text_plain);
Expect("Decrypted text", exp_text, text_plain);
document.getElementById("text_plain").innerHTML = text_plain;
/* -------------------------------------------------------------------------- */
