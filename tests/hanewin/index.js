/**
 * Unit test for haneWIN OpenPGP implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 */

module("haneWIN tests");

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


test('Get secret key details',function(){
    var result = OpenPGP_GetSecretInformation(key_sec);
    equals(result['u'], exp_u, "Secret u");
    equals(result['d'], exp_d, "Secret d");
    equals(result['p'], exp_p, "Secret p");
    equals(result['q'], exp_q, "Secret q");
})

test('Get public key details',function(){
    var result = OpenPGP_GetPublicInformation(key_pub);
    equals(result['mpi'], exp_mpi, "Public MPIs");
    equals(result['id'], exp_id, "Public ID");
})

test('Encrypt test',function(){
    var info = OpenPGP_GetPublicInformation(key_pub);
    var keytype = 0; // 0=RSA, 1=Elgamal
    var text_enc = OpenPGP_Encrypt(
                             info['id'],
                             keytype,
                             info['mpi'],
                             exp_text);
    equals(text_enc.split(["\n"])[0],
           "-----BEGIN PGP MESSAGE-----",
           "Encrypted text");
})


test('Decrypt test',function(){
    var pubInfo = OpenPGP_GetPublicInformation(key_pub);
    var secInfo = OpenPGP_GetSecretInformation(key_sec);
    var keytype = 0; // 0=RSA, 1=Elgamal

    var text_enc = OpenPGP_Encrypt(
                             pubInfo['id'],
                             keytype,
                             pubInfo['mpi'],
                             exp_text);

    var text_plain = OpenPGP_Decrypt(
                               secInfo['p'],
                               secInfo['q'],
                               secInfo['d'],
                               secInfo['u'],
                               text_enc);
    equals(text_plain, exp_text, "Decrypted text");
})

