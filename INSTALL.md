# Installation instructions
Run the following commands:

    make
    make html
    make man
    lynx doc/iputils.html
    # Read...

## Troubleshooting
If the first `make` fails, no problems:

    make html
    lynx doc/iputils.html
    Read section "Installation notes"...

But if `make html` fails too, check that DocBook package is installed
on your machine. If it is installed, and `make` does not work nevertheless,
please [open an issue on github.com]
(https://github.com/iputils/iputils/issues/new).

## Install into a prefix
There's no `configure` option to install into a prefix. Use the `DESTDIR` 
`make` variable to change the installation target. There's no support for 
picking up build dependencies in a prefix.

