# Copyright (c) Iputils Project, 2018-2020
#
# Update iputils.pot:
# meson . builddir && ninja iputils-pot -C builddir
#
# Update *.po files
# meson . builddir && ninja iputils-update-po -C builddir

i18n = import('i18n')
i18n.gettext(meson.project_name(), args: '--directory=' + meson.source_root())
