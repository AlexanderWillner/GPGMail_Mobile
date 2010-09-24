#!/bin/sh
echo "CACHE MANIFEST" > gpgmail.manifest
find . -type f|grep -vE ".git|README|htaccess|manifest"|sed "s/\.\///g" >> gpgmail.manifest