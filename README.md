Oath
====

Oath is a One Time Password library mostly known as authenticators in Google's Two-Step Verification and similar products. It covers bose HOTP and TOTP based on their RFC descriptions.


Description of Oath
===================

It implements the Two Step Authentication specified in RFC6238 @ http://tools.ietf.org/html/rfc6238 using OATH and compatible with Google Authenticator App for android. It uses a 3rd party class called Base32 for RFC3548 base 32 encode/decode. Feel free to use better adjusted implementation.

Special Thanks goes to
======================

phil@idontplaydarts.com for this article https://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/
Wikipedia.org for this article http://en.wikipedia.org/wiki/Google_Authenticator
devicenull@github.com for this class https://github.com/devicenull/PHP-Google-Authenticator/blob/master/base32.php
