#!/bin/sh
# postinstall.sh — kbounce post-install notice
# Printed after dpkg/rpm installs the package.
# Does NOT require sudo to run the binary itself.
set -e

echo ""
echo "kbounce installed to /usr/local/bin/kbounce"
echo ""
echo "Verify your install:"
echo "  kbounce --version"
echo ""
echo "Quick start:"
echo "  kbounce run --upstream https://<your-kube-apiserver>"
echo ""
echo "Docs: https://github.com/trsreagan3/kbouncer/blob/main/README.md"
echo ""
