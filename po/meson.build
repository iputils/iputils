# Update iputils.pot with the following command:
# find . -name '*.[hc]' | xargs xgettext --keyword=_ --language=C --add-comments --sort-output --package-name=iputils -o po/iputils.pot

i18n = import('i18n')
i18n.gettext(meson.project_name(), args: '--directory=' + meson.source_root())
