/**
 * Main script for GPGMail_Mobile.
 *
 * @author  Alexander Willner <alex@willner.ws>
 * @version 2011-02-22
 * @see     http://gpgtools.org
 * @license BSD
 * @todo    implement more functionalities
 */

$(document).ready(function(){
    $("#homeScreenInfo").html($.i18n._('homeScreenInfo'));
    $("#encryptButtonFront").html($.i18n._('encryptButtonFront'));
    $("#decryptButtonFront").html($.i18n._('decryptButtonFront'));
    $("#infoButton").html($.i18n._('infoButton'));
    $("#optionsButton").html($.i18n._('optionsButton'));
    $("#donateButton").html($.i18n._('donateButton'));
});
