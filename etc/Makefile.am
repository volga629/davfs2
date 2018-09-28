## Makefile for etc directory in davfs.
## Copyright (C) 2006, 2007, 2008, 2009 Werner Baumann
##
## This file is part of davfs2.
##
## davfs2 is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## davfs2 is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with davfs2; if not, write to the Free Software Foundation,
## Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA. */

## Process this file with automake to produce Makefile.in

dist_pkgdata_DATA = davfs2.conf secrets
pkgsysconfdir = $(sysconfdir)/@PACKAGE@

install-data-local: $(dist_pkgdata_DATA)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir)
	$(INSTALL_DATA) -b davfs2.conf $(DESTDIR)$(pkgsysconfdir)/davfs2.conf
	$(INSTALL_DATA) -b -m 600 secrets $(DESTDIR)$(pkgsysconfdir)/secrets
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir)/certs
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir)/certs/private
	chmod 700 $(DESTDIR)$(pkgsysconfdir)/certs/private

uninstall-local:
	@$(NORMAL_UNINSTALL)
	@list='$(dist_pkgdata_DATA)'; for p in $$list; do \
	  f="`echo $$p | sed -e 's|^.*/||'`"; \
	  echo " rm -f $(DESTDIR)$(pkgsysconfdir)/$$f"; \
	  rm -f $(DESTDIR)$(pkgsysconfdir)/$$f; \
	done
