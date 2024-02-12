#!/bin/sh -eu
# Copyright (c) 2023 Petr Vorel <pvorel@suse.cz>
# Create tarballs and checksums for uploading after tagging a new release.
# NOTE: 0.58.0 (at least) is required (for meson dist --formats "$formats")
# Run release with a reasonably new meson.

basedir="$(dirname "$0")"
. "$basedir/lib.sh"
require_cmd date git gpg meson sha256sum

tag="$(date +%Y%m%d)"
tarball_dir="iputils-full-$tag"
git_dir=$(cd "$basedir/.."; pwd)
dir="$(cd "$git_dir/../"; pwd)/iputils-release-$tag"
dist=builddir
formats="xztar,gztar,zip"

# check output directory
if [ -d "$dir" ]; then
	ask "Directory '$dir' exists, will be deleted"
	rm -rf "$dir"
fi
rod mkdir "$dir"
cd "$dir"
dir="$PWD"

# git clone (local)
title "git clone"
rod git clone "$git_dir" "$tarball_dir"
rod cd "$tarball_dir"

# check for tag
if ! git show "$tag" 2> /dev/null; then
	ask "Tag '$tag' does not exist, you should run tag-release.sh before, otherwise meson creates archive for $(git describe --abbrev=0)"
fi

# tarballs
title "Generate tarballs"
rod meson "$dist"
rod meson dist -C "$dist" --formats "$formats"

cd "$dist/meson-dist/"

title "Generate tarballs and checksums"
# meson puts '*' before filename in checksums (unusable for distros => need to
# recreate them)
rm -f ./*.sha256sum

for file in *.*; do
	gpg --sign --armor --detach-sign "$file"
	sha256sum "$file" >> sha256sums
done

# sha256sums.asc (GPG signed checksums)
gpg --clearsign sha256sums
rm -f sha256sums

mv -v ./* "$dir"

echo
title "Generated tarballs and checksums"
cd "$dir" && ls -p | grep -v /
echo
echo "Files are in '$dir', upload them to github"
