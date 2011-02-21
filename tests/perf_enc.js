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
var exp_mpi = "BADiejt3X/biElrPwczuou+GxI1eVbbb0mAS5Eek0h8SKGBO9cHC/tj3uWG/bF6A2+q0WLj+46mI9j60drz5osu3aerjZkiZiGFj9GhdnvYZ7ErT+wV8koxj/2Lrbq8iQyfNpj76VqTl7Rl09BaR/eSm6o6mQ1clqqiEV0FOcTi30wARAQAB";
var exp_id = "a99b311c7f20062a";
var exp_text = randomString(1);
/* -------------------------------------------------------------------------- */

test('Encrypt test',function(){
    var text_enc = OpenPGP_Encrypt(
                             exp_id,
                             0,
                             exp_mpi,
                             exp_text);
    equals(text_enc.split(["\n"])[0],
           "-----BEGIN PGP MESSAGE-----",
           "Encrypted text");
})

function randomString(length) {
	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
	var randomstring = '';
	for (var i=0; i<length; i++) {
		var rnum = Math.floor(Math.random() * chars.length);
		randomstring += chars.substring(rnum,rnum+1);
	}
	return randomstring;
}
