Limiting the possible Access-Control-Allow-Origin values to a set of allowed
origins requires code on the server side to check the value of the Origin
request header, compare that to a list of allowed origins, and then if the
Origin value is in the list, to set the Access-Control-Allow-Origin value to
the same value as the Origin value.


This note from Chrome:
https://chromium.googlesource.com/chromium/src/+/master/content/browser/webauth/uv_preferred.md

More bugs from Firefox:
https://bugzilla.mozilla.org/show_bug.cgi?id=1609393

Firefox doesn't support CTAP2 at all yet:
https://bugzilla.mozilla.org/show_bug.cgi?id=1530373
https://bugzilla.mozilla.org/show_bug.cgi?id=1530370

What this means in practice I think is that you _need_ to tell what credentials to use
