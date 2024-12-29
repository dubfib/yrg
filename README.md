# cert
> more of a WIP project, eventually going to be apart of yrg (main branch)

## usage
```bash
$ cert Discord.exe
```

## generated rule example
```yara
/**
    Generated using yrg (yara-rule-generator)
    https://github.com/dubfib/yrg
*/

import "pe"

rule certificate_0de9cf2e718364a0062e0d83093e34d7 {
    meta:
        author = "dubfib"
        date = "2024-12-29"

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Discord Inc." and
            pe.signatures[i].serial == "0d:e9:cf:2e:71:83:64:a0:06:2e:0d:83:09:3e:34:d7" and
            1821830399 <= pe.signatures[i].not_after
        )
}
```

##### © Copyright 2024 dubfib - [MIT License](https://github.com/dubfib/yrg/blob/cert/LICENSE)
