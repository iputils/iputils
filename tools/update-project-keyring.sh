#!/bin/sh
# Copyright (c) 2019 Petr Vorel <petr.vorel@gmail.com>

keys="902265EB1ECF3AD10BDF80D84807F894E0620EEA" # YOSHIFUJI Hideaki
keys="73540C3F796DC1C30ECACCAC9FC5E7B74A45D0DE 5192BA645ED64BC326D3E0114A8D0987698B0274 $keys" # David Heidelberg
keys="25999B407FB6A9B701BBF1E40D46FEF7E61DBB46 8ED396E37E38D471A00530D3A9553245FDE9B739 $keys" # Sami Kerola
keys="33C58482C402292D2E3C5C069709F90C3C96FFC8 $keys" # Thomas Deutschmann
keys="2016FEA4858B1C36B32E833AC0DEC2EE72F33A5F $keys" # Petr Vorel
keys="5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23 $keys" # GitHub (web-flow commit signing)

out="$(dirname "$0")/../Documentation/project-keys.gpg"
in="iputils-maintainer-keys.gpg"

gpg --no-default-keyring --keyring "$in" --recv-keys $keys
rm -f "$out"
gpg --no-default-keyring --keyring "$in" --export --armor --output "$out"
rm -f ~/.gnupg/"$in"
