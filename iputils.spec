#
# This spec file is for _testing_.
#

%define ssdate 20121221
Summary: The ping program for checking to see if network hosts are alive.
Name: iputils
Version: s%{ssdate}
Release: 1local
License: GPLv2+
Group: System Environment/Daemons
Source0: iputils-s%{ssdate}.tar.bz2
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-root
#BuildPrereq: docbook-dtd31-sgml, perl
Requires: kernel >= 2.4.7

%description
The iputils package contains ping, a basic networking tool.  The ping
command sends a series of ICMP protocol ECHO_REQUEST packets to a
specified network host and can tell you if that machine is alive and
receiving network traffic.

%prep
%setup -q %{name}

%build
make
make ninfod
make man
make html

%install
rm -fr ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}%{_sbindir}
mkdir -p ${RPM_BUILD_ROOT}%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{_unitdir}

install -c clockdiff            ${RPM_BUILD_ROOT}%{_sbindir}/
install -cp arping              ${RPM_BUILD_ROOT}%{_sbindir}/
install -cp ping                ${RPM_BUILD_ROOT}%{_bindir}/
install -cp rdisc               ${RPM_BUILD_ROOT}%{_sbindir}/
install -cp ping6               ${RPM_BUILD_ROOT}%{_bindir}/
install -cp tracepath           ${RPM_BUILD_ROOT}%{_bindir}/
install -cp tracepath6          ${RPM_BUILD_ROOT}%{_bindir}/
install -cp ninfod/ninfod       ${RPM_BUILD_ROOT}%{_sbindir}/

mkdir -p ${RPM_BUILD_ROOT}%{_bindir}
ln -sf ../bin/ping6 ${RPM_BUILD_ROOT}%{_sbindir}
ln -sf ../bin/tracepath ${RPM_BUILD_ROOT}%{_sbindir}
ln -sf ../bin/tracepath6 ${RPM_BUILD_ROOT}%{_sbindir}

mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man8
install -cp doc/clockdiff.8     ${RPM_BUILD_ROOT}%{_mandir}/man8/
install -cp doc/arping.8        ${RPM_BUILD_ROOT}%{_mandir}/man8/
install -cp doc/ping.8          ${RPM_BUILD_ROOT}%{_mandir}/man8/
install -cp doc/rdisc.8         ${RPM_BUILD_ROOT}%{_mandir}/man8/
install -cp doc/tracepath.8     ${RPM_BUILD_ROOT}%{_mandir}/man8/
install -cp doc/ninfod.8        ${RPM_BUILD_ROOT}%{_mandir}/man8/
ln -s ping.8.gz ${RPM_BUILD_ROOT}%{_mandir}/man8/ping6.8.gz
ln -s tracepath.8.gz ${RPM_BUILD_ROOT}%{_mandir}/man8/tracepath6.8.gz

iconv -f ISO88591 -t UTF8 RELNOTES -o RELNOTES.tmp
touch -r RELNOTES RELNOTES.tmp
mv -f RELNOTES.tmp RELNOTES

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%doc RELNOTES
%attr(0755,root,root) %caps(cap_net_raw=ep) %{_sbindir}/clockdiff
#%attr(4755,root,root) %{_sbindir}/clockdiff
%attr(0755,root,root) %caps(cap_net_raw=ep) %{_sbindir}/arping
#%attr(4755,root,root) %{_sbindir}/arping
%attr(0755,root,root) %caps(cap_net_raw=ep cap_net_admin=ep) %{_bindir}/ping
#%attr(4755,root,root) %{_bindir}/ping
%attr(0755,root,root) %caps(cap_net_raw=ep cap_net_admin=ep) %{_bindir}/ping6
#%attr(4755,root,root) %{_bindir}/ping6
%{_sbindir}/rdisc
%{_bindir}/tracepath
%{_bindir}/tracepath6
%{_sbindir}/ping6
%{_sbindir}/tracepath
%{_sbindir}/tracepath6
%{_sbindir}/ninfod
%attr(644,root,root) %{_mandir}/man8/*

%changelog
* Fri Nov 30 2012 YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
  Partically sync with current Fedora's specfile.
* Sat Feb 23 2001 Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
  Taken iputils rpm from ASPLinux-7.2 as pattern.
