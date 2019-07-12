#!/bin/sh

keys="4807F894E0620EEA" # YOSHIFUJI Hideaki
keys="9FC5E7B74A45D0DE 4A8D0987698B0274 $keys" # David Heidelberg
keys="25999B407FB6A9B701BBF1E40D46FEF7E61DBB46 8ED396E37E38D471A00530D3A9553245FDE9B739 $keys" # Sami Kerola
keys="33C58482C402292D2E3C5C069709F90C3C96FFC8 $keys" # Thomas Deutschmann
keys="2016FEA4858B1C36B32E833AC0DEC2EE72F33A5F $keys" # Petr Vorel
keys="4AEE18F83AFDEB23 $keys" # GitHub (web-flow commit signing)

out="$(dirname $0)/../Documentation/project-keys.gpg"
in="iputils-maintainer-keys.gpg"

gpg --no-default-keyring --keyring $in --recv-keys $keys
rm -f $out
gpg --no-default-keyring --keyring $in --export --armor --output $out
rm -f ~/.gnupg/$in
