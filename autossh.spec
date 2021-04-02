Summary:	Automatically restart SSH sessions and tunnels
Name:		autossh
Version:	1.4b
Release:	1
License:	Distributable
Group:		Applications/Networking
Vendor:		Carson Harding <harding@motd.ca>
URL:		http://www.harding.motd.ca/autossh/
Source0:	%{name}-%{version}.tgz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description
autossh is a program to start a copy of ssh and monitor it, restarting
it as necessary should it die or stop passing traffic.

%prep
%setup -q

%build
%configure

%{__make}

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT{%{_bindir},%{_mandir}/man1}

install autossh $RPM_BUILD_ROOT%{_bindir}
install autossh.1 $RPM_BUILD_ROOT%{_mandir}/man1

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%doc README CHANGES autossh.host rscreen
%attr(755,root,root) %{_bindir}/*
%{_mandir}/man1/*

%changelog
* Fri Mar 28 2008 Carson Harding <harding@motd.ca>
- update to 1.4b

* Sat May 20 2006 Carson Harding <harding@motd.ca>
- update to 1.4 and use autoconf

* Wed Feb 02 2005 Carson Harding <harding@motd.ca>
- very minor changes to spec file

* Thu Oct 21 2004 Ron Yorston <rmy@tigress.co.uk> 1.3-1
- Original version
