#!/bin/sh -eu
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2023 Petr Vorel <pvorel@suse.cz>
# Tag iputils release.

basedir="$(dirname "$0")"
cd "$basedir/.."
. "$basedir/lib.sh"

require_cmd date git sed sort uniq

upstream_git="iputils/iputils"
tag="$(date +%Y%m%d)"
old_tag="$(git describe --abbrev=0)"
tag_msg="iputils-$tag"
credit="/tmp/$(basename $upstream_git)-release-$tag"

# repository checks
if ! git ls-remote --get-url origin | grep -q $upstream_git; then
	quit "Not an upstream project"
fi

if ! git --no-pager diff --exit-code || ! git --no-pager diff --staged --exit-code; then
	quit "Please commit your changes before making new release"
fi

if [ "$(git branch --show-current)" != "master" ]; then
    quit "not on master branch"
fi

if git show "$tag" 2> /dev/null; then
	quit "Tag '$tag' already exists"
fi

if grep -q "version.*$tag" meson.build; then
	quit "Tag '$tag' already in meson.build file"
fi

title "git tag"
echo "new tag: '$tag', previous tag: '$old_tag'"
sed --in-place "s/version : '.*')/version : '$tag')/" meson.build
git add meson.build
rod git commit -S --signoff --message "release: $tag_msg" meson.build
rod git tag --sign --annotate "$tag" --message "$tag_msg"
git --no-pager show "$tag" --show-signature

ask "Please check tag and signature"

title "Creating skeletion of the contributions"
cat > "$credit" <<EOF
TODO: Add changelog

## credit
Many thanks to the developers contributing to this release:
\`\`\`
    $ git shortlog -sen $old_tag.. -- \$(git ls-files | grep -v ^po/)
EOF
git shortlog -sen "$old_tag".. -- $(git ls-files | grep -v ^po/) .github/ >> "$credit"

cat >> "$credit" <<EOF
\`\`\`

and translators:
\`\`\`
    $ git shortlog -sen $old_tag.. -- po/
EOF
git shortlog -sen "$old_tag".. -- po/ >> "$credit"

cat >> "$credit" <<EOF
\`\`\`

Also thanks to patch reviewers and co-developers:

\`\`\`
$ git log $old_tag.. | grep -Ei '(reviewed|acked|co-developed)-by:' | sed 's/.*by: //' | sort | uniq -c | sort -n -r
EOF

git log "$old_tag".. | grep -Ei '(reviewed|acked|co-developed)-by:' | sed 's/.*by: //' | sort | uniq -c | sort -n -r >> "$credit"

cat >> "$credit" <<EOF
\`\`\`

and testers:
\`\`\`
$ git log $old_tag.. | grep -Ei 'tested-by:' | sed 's/.*by: //' | sort | uniq -c | sort -n -r
EOF
git log "$old_tag".. | grep -Ei 'tested-by:' | sed 's/.*by: //' | sort | uniq -c | sort -n -r >> "$credit"
echo '```'  >> "$credit"

echo "skeleton of the contributions is in $credit"

title "git push"
ask "Pushing changes to upstream git"
rod git push origin master:master
git push origin "$tag"
