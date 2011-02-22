#!/bin/sh
##
 # Manifest creation script for GPGMail_Mobile.
 #
 # @author  Alexander Willner <alex@willner.ws>
 # @version 2011-02-22
 # @see     http://gpgtools.org
 # @license BSD
 # @todo    Nothing.
 #
echo "CACHE MANIFEST" > gpgmail.manifest
find . -type f|grep -vE ".git|README|htaccess|manifest"|sed "s/\.\///g" >> gpgmail.manifest
