#!/bin/bash

set -e

if [ "$(basename $(pwd))" != "client-rpc" ]; then
    echo "Error: you must run this from the docs/client-rpc directory" >&2
    exit 1
fi

rm -rf api

docsify init --local api

rm -f api/README.md

if [ -n "$NPM_PACKAGES" ]; then
    npm_dir="$NPM_PACKAGES/lib/node_modules"
elif [ -n "$NODE_PATH" ]; then
    npm_dir="$NODE_PATH"
elif [ -d "$HOME/node_modules" ]; then
    npm_dir="$HOME/node_modules"
elif [ -d "/usr/local/lib/node_modules" ]; then
    npm_dir="/usr/local/lib/node_modules"
else
    echo "Can't determine your node_modules path; set NPM_PACKAGES or NODE_PATH appropriately" >&2
    exit 1
fi

cp $npm_dir/docsify/node_modules/prismjs/components/prism-{json,python,c,cpp}.min.js api/vendor

./rpc-to-markdown.py client_rpc_endpoints.h "$@"

perl -ni -e '
BEGIN { $first = 0; }
if (m{^\s*<script>\s*$} .. m{^\s*</script>\s*$}) {
    if (not $first) {
        $first = false;
        print qq{
  <script>
    window.\$docsify = {
      name: "Oxen Storage Server RPC",
      repo: "https://github.com/oxen-io/oxen-storage-server",
      loadSidebar: "sidebar.md",
      subMaxLevel: 3,
      homepage: "index.md",
      latex: {
        inlineMath   : [["\$", "\$"]],
        displayMath  : [["\$\$", "\$\$"]],
      },
    }
  </script>\n};
    }
} else {
    s{<title>.*</title>}{<title>Oxen Storage Server RPC</title>};
    s{(name="description" content=)"[^"]*"}{$1"Oxen Storage Server RPC endpoint documentation"};
    if (m{^\s*</body>}) {
        print qq{
  <script src="vendor/prism-json.min.js"></script>
  <script type="text/javascript" id="MathJax-script" src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/docsify-latex@0"></script>
};
    }
    print;
}' api/index.html
