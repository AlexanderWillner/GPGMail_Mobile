/**
 * Unit test for haneWIN OpenPGP implementation.
 *
 * @author  Alexander Willner <alex@willner.ws>
 */

module("haneWIN tests");

/* test data ---------------------------------------------------------------- */
var key_sec = ReadFile("data/test.gpg.secret.asc");
var key_pub = ReadFile("data/test.gpg.public.asc");
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
var exp_u = "128,262841242,182804438,87204373,93572779,30267070,158877147,159192324,65059055,255818079,255869047,50106253,260497065,177113489,19189000,133621822,70672351,39455161,61068122,133062127,200233467,85835182,137123654,162783743,1974060,146287404,144723935,86045567,161679681,167326372,248878193,118345519,254401541,73018319,123790798,209880418,75932170,52882";
var exp_d = "256,79835921,119466303,121414380,181765629,2385002,180722037,238466499,22473911,206397250,255759451,224041648,192616279,8491175,122357715,187594198,74398690,116184881,56920272,82608358,91077291,112581838,177855197,90896813,93317939,116228988,111820677,135360813,47748600,98663351,55070804,71665024,176913722,238252034,130268354,211433517,145778876,258643440,85741786,28297295,246353531,59155769,42207752,75544410,36491651,240008166,235821070,12932226,191193096,238442510,258607869,72394155,161634708,127060471,39991388,149796968,80290816,194164237,75042546,159353412,145488291,106188858,199091193,238974861,256553683,114991543,6563953,95970601,166409906,192367873,22175884,127359,20753421,53984141,6";
var exp_p = "128,254811031,201598675,11086392,37809158,61736702,184194356,236048260,26579453,232422908,182950282,251968183,134212720,229356446,123241900,173837631,246810084,159108436,31954478,36926796,6861171,34369878,243581160,215446764,213256527,69929757,140133100,104426535,111793831,12792963,192939175,95971408,164249112,90432455,238829153,138543473,147177517,54322";
var exp_q = "128,48249849,173581060,208090803,128794725,42378432,259974304,115060649,260183401,12579304,131608989,189862248,159698743,239751369,162452152,89319153,236614211,147675411,222100612,250666875,209345238,186969937,229390904,117274963,175546932,163516074,237444684,35028363,193199635,263730770,193029745,168916055,11390613,226451583,7859714,233532882,87540907,62234";
var exp_mpi = "CADB4pQwzfZ+UNCx1urFNZKXvQ1zZxIbBuj050Hc4moyta1a9wwAt+n+OgaaeYndrfC1L+AYlszAiIUvDc7IR+hepTPTQsN6JAvU/kPls4y9pEQEBtInTHsaq4RzTtK3qgiRDA6WS7LUOq0yPNYIIszuIN/4G/CuZfITi2adcXohlc3Nl+TvPm8lkCFckb40GApewXpc2vXg+TS7z6E/orHPudhje6ULErjbEggBw4NiwhDOiftIH7mFGZ+DSpgnbArQk1ZEtnhIh0oAKqS4MY+b7h5vcJLSZYVECmoj2W178wXld9hXwjGj3frmG8VNnFnTAHBMsvK5HrjPghhrd8/HABEBAAE=";
var exp_id = "78c156ef01ab4555";
var exp_text = "a test string\r\n";
/* -------------------------------------------------------------------------- */


test('Get secret key details',function(){
    var result = doDecrypt([], [], [], [], key_sec);
    var result_u = GetKeyValue(result, "u");
    var result_d = GetKeyValue(result, "d");
    var result_p = GetKeyValue(result, "p");
    var result_q = GetKeyValue(result, "q");
    equals(result_u, exp_u, "Secret u");
    equals(result_d, exp_d, "Secret d");
    equals(result_p, exp_p, "Secret p");
    equals(result_q, exp_q, "Secret q");
})

test('Get public key details',function(){
    var pu=new getPublicKey(key_pub);
    var pubkey = pu.pkey.replace(/\n/g,'');
    var keyid = pu.keyid;
    equals(pubkey, exp_mpi, "Public MPIs");
    equals(keyid, exp_id, "Public ID");
})

test('Encrypt test',function(){
    var pu=new getPublicKey(key_pub);
    var pubkey = pu.pkey.replace(/\n/g,'');
    var keyid = pu.keyid;
    var keytype = 0; // 0=RSA, 1=Elgamal
    var text_enc = doEncrypt(keyid,
                             keytype,
                             pubkey,
                             exp_text);
    equals(text_enc.split(["\n"])[0],
           "-----BEGIN PGP MESSAGE-----",
           "Encrypted text");
})

test('Decrypt test',function(){
    var result = doDecrypt([], [], [], [], key_sec);
    var result_u = GetKeyValue(result, "u");
    var result_d = GetKeyValue(result, "d");
    var result_p = GetKeyValue(result, "p");
    var result_q = GetKeyValue(result, "q");

    var pu=new getPublicKey(key_pub);
    var pubkey = pu.pkey.replace(/\n/g,'');
    var keyid = pu.keyid;
    var keytype = 0; // 0=RSA, 1=Elgamal
    var text_enc = doEncrypt(keyid,
                             keytype,
                             pubkey,
                             exp_text);

    var text_plain = doDecrypt(result_p.split(","),
                               result_q.split(","),
                               result_d.split(","),
                               result_u.split(","),
                               text_enc);

    equals(text_plain, exp_text, "Decrypted text");
})

