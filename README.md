# Gookies

Similar to the excellent SharpChrome project, the tool will decrypt the Chrome cookie store and display them either in a JSON format ready for import into your cookie manager, for example EditThisCookie or alternately a canonicalised cookie header for use within command line tools like curl.

The tool currently supports multiple Chrome profiles, domain listing, domain filter and output format and also support from Chrome 80+ which has a different cookie encryption scheme to version 79 or below.

```bash
Usage of gookies.exe:
   -domain string
         Show the canonicalised cookie value for a specific domain
   -format string
         The output format: string, json (default) (default "json")
   -profile int
         Which Chrome profile index to extract cookie data from, uses Default when not specified
   -profiles
         Lists the profile names and index to Chrome profiles under this account
   -storeId string
         The storeId to embed in exported JSON, incognito is storeId 1 in Chrome (default "0")
```
Currently gookies only supports Windows, but the plan is to add support for Linux and MacOS with the added bonus of no dependency binaries produced by Go.

