#$algos=@("ADLER-32","CRC-32" , "CRC-32B" , "CRC-16","CRC-16-CCITT","DES(Unix)","FCS-16","GHash-32-3","GHash-32-5","GOST R 34.11-94","Haval-160","Haval-160(HMAC)","Haval-192" , "Haval-192(HMAC)" , "Haval-224" , "Haval-224(HMAC)" , "Haval-256" , "Haval-256(HMAC)" , "Lineage II C4" , "Domain Cached Credentials - MD4(MD4((pass)).(strtolower(username)))" , "XOR-32" , "MD5(Half)" , "MD5(Middle)" , "MySQL" , "MD5(phpBB3)" , "MD5(Unix)" , "MD5(Wordpress)" , "MD5(APR)" , "Haval-128" , "Haval-128(HMAC)" , "MD2" , "MD2(HMAC)" , "MD4" , "MD4(HMAC)" , "MD5" , "MD5(HMAC)" , "MD5(HMAC(Wordpress))" , "NTLM" , "RAdmin v2.x" , "RipeMD-128" , "RipeMD-128(HMAC)" , "SNEFRU-128" , "SNEFRU-128(HMAC)" , "Tiger-128" , "Tiger-128(HMAC)" , "md5(`$pass.`$salt)" , "md5(`$salt."-".md5(`$pass))" , "md5(`$salt.`$pass)" , "md5(`$salt.`$pass.`$salt)" , "md5(`$salt.`$pass.`$username)" , "md5(`$salt.md5(`$pass))" , "md5(`$salt.md5(`$pass).`$salt)" , "md5(`$salt.md5(`$pass.`$salt))" , "md5(`$salt.md5(`$salt.`$pass))" , "md5(`$salt.md5(md5(`$pass).`$salt))" , "md5(`$username.0.`$pass)" , "md5(`$username.LF.`$pass)" , "md5(`$username.md5(`$pass).`$salt)" , "md5(md5(`$pass))" , "md5(md5(`$pass).`$salt)" , "md5(md5(`$pass).md5(`$salt))" , "md5(md5(`$salt).`$pass)" , "md5(md5(`$salt).md5(`$pass))" , "md5(md5(`$username.`$pass).`$salt)" , "md5(md5(md5(`$pass)))" , "md5(md5(md5(md5(`$pass))))" , "md5(md5(md5(md5(md5(`$pass)))))" , "md5(sha1(`$pass))" , "md5(sha1(md5(`$pass)))" , "md5(sha1(md5(sha1(`$pass))))" , "md5(strtoupper(md5(`$pass)))" , "MySQL5 - SHA-1(SHA-1(`$pass))" , "MySQL 160bit - SHA-1(SHA-1(`$pass))" , "RipeMD-160(HMAC)" , "RipeMD-160" , "SHA-1" , "SHA-1(HMAC)" , "SHA-1(MaNGOS)" , "SHA-1(MaNGOS2)" , "Tiger-160" , "Tiger-160(HMAC)" , "sha1(`$pass.`$salt)" , "sha1(`$salt.`$pass)" , "sha1(`$salt.md5(`$pass))" , "sha1(`$salt.md5(`$pass).`$salt)" , "sha1(`$salt.sha1(`$pass))" , "sha1(`$salt.sha1(`$salt.sha1(`$pass)))" , "sha1(`$username.`$pass)" , "sha1(`$username.`$pass.`$salt)" , "sha1(md5(`$pass))" , "sha1(md5(`$pass).`$salt)" , "sha1(md5(sha1(`$pass)))" , "sha1(sha1(`$pass))" , "sha1(sha1(`$pass).`$salt)" , "sha1(sha1(`$pass).substr(`$pass,0,3))" , "sha1(sha1(`$salt.`$pass))" , "sha1(sha1(sha1(`$pass)))" , "sha1(strtolower(`$username).`$pass)" , "Tiger-192" , "Tiger-192(HMAC)" , "md5(`$pass.`$salt) - Joomla" , "SHA-1(Django)" , "SHA-224" , "SHA-224(HMAC)" , "RipeMD-256" , "RipeMD-256(HMAC)" , "SNEFRU-256" , "SNEFRU-256(HMAC)" , "SHA-256(md5(pass))" , "SHA-256(sha1(pass))" , "SHA-256" , "SHA-256(HMAC)" , "md5(`$pass.`$salt) - Joomla" , "SAM - (LM_hash:NT_hash)" , "SHA-256(Django)" , "RipeMD-320" , "RipeMD-320(HMAC)" , "SHA-384" , "SHA-384(HMAC)" , "SHA-256" , "SHA-384(Django)" , "SHA-512" , "SHA-512(HMAC)" , "Whirlpool" , "Whirlpool(HMAC)")
#$exemples=@("0607cb42" , "4607" , "3d08" , "b33fd057" , "b764a0d9" , "ZiY8YtDKXJwYQ" , "f42005ec1afe77967cbc83dce1b4d714" , "0e5b" , "80000000" , "85318985" , "ab709d384cce5fda0793becd3da0cb6a926c86a8f3460efb471adddee1c63793" , "d6e3ec49aa0f138a619f27609022df10" , "3ce8b0ffd75bc240fc7d967729cd6637" , "a106e921284dd69dad06192a4411ec32fce83dbb" , "29206f83edc1d6c3f680ff11276ec20642881243" , "cd3a90a3bebd3fa6b6797eba5dab8441f16a7dfa96c6e641" , "39b4d8ecf70534e2fd86bb04a877d01dbf9387e640366029" , "f65d3c0ef6c56f4c74ea884815414c24dbf0195635b550f47eac651a" , "f10de2518a9f7aed5cf09b455112114d18487f0c894e349c3c76a681" , "7169ecae19a5cd729f6e9574228b8b3c91699175324e6222dec569d4281d4a4a" , "6aa856a2cfd349fb4ee781749d2d92a1ba2d38866e337a4a1db907654d4d4d7a" , "0x49a57f66bd3d5ba6abda5579c264a0e4" , "08bbef4754d98806c373f2cd7d9a43c4" , "4b61b72ead2b0eb0fa3b8a56556a6dca" , "a2acde400e61410e79dacbdfc3413151" , "6be20b66f2211fe937294c1c95d1cd4f" , "ae11fd697ec92c7c98de3fac23aba525" , "`$apr1`$qAUKoKlG`$3LuCncByN76eLxZAh/Ldr1" , "d57e43d2c7e397bf788f66541d6fdef9" , "3f47886719268dfa83468630948228f6" , "`$H`$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1" , "`$1`$cTuJH0Ju`$1J8rI.mJReeMvpKUZbSlY/" , "`$P`$BiTOhOj3ukMgCci2juN0HRbCdDRqeh." , "ae11fd697ec92c7c" , "7ec92c7c98de3fac" , "35d1c0d69a2df62be2df13b087343dc9:BeKMviAfcXeTPTlX" , "fb33e01e4f8787dc8beb93dac4107209:fxJUXVjYRafVauT77Cze8XwFrWaeAYB2" , "63cea4673fd25f46" , "9bb2fb57063821c762cc009f7584ddae9da431ff" , "*2470c0c06dee42fd1618bb99005adca2ec9d1e19" , "cc348bace876ea440a28ddaeb9fd3550" , "baea31c728cbf0cd548476aa687add4b" , "4985351cd74aff0abc5a75a0c8a54115" , "ae1995b931cf4cbcf1ac6fbf1a83d1d3" , "dc65552812c66997ea7320ddfb51f5625d74721b" , "ca28af47653b4f21e96c1235984cb50229331359" , "5fcbe06df20ce8ee16e92542e591bdea706fbdc2442aecbf42c223f4461a12af" , "43227322be1b8d743e004c628e0042184f1288f27c13155412f08beeee0e54bf" , "b4f7c8993a389eac4f421b9b3b2bfb3a241d05949324a8dab1286069a18de69aaf5ecc3c2009d8ef" , "244516688f8ad7dd625836c0d0bfc3a888854f7c0161f01de81351f61e98807dcd55b39ffe5d7a78" , "4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5" , "4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333" , "sha1`$Zion3R`$299c3d65a0dcab1fc38421783d64d0ecf4113448" , "6f5daac3fee96ba1382a09b1ba326ca73dccf9e7" , "a2c0cdb6d1ebd1b9f85c6e25e0f8732e88f02f96" , "644a29679136e09d0bd99dfd9e8c5be84108b5fd" , "e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59" , "c15ff86a859892b5e95cdfd50af17d05268824a6c9caaa54e4bf1514" , "2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e" , "`$6`$g4TpUQzk`$OmsZBJFwvy6MwZckPvVYfDnwsgktm2CckOlNJGy9HNwHSuHFvywGIuwkJ6Bjn3kKbB6zoyEjIYNMpHWBNxJ6g." , "sha256`$Zion3R`$9e1a08aa28a22dfff722fad7517bae68a55444bb5e2f909d340767cec9acf2c3" , "d3dd251b7668b8b6c12e639c681e88f2c9b81105ef41caccb25fcde7673a1132" , "b419557099cfa18a86d1d693e2b3b3e979e7a5aba361d9c4ec585a1a70c7bde4" , "afbed6e0c79338dbfe0000efe6b8e74e3b7121fe73c383ae22f5b505cb39c886" , "3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b" , "sha384`$Zion3R`$88cfd5bc332a4af9f09aa33a1593f24eddc01de00b84395765193c3887f4deac46dc723ac14ddeb4d3a9b958816b7bba" , "bef0dd791e814d28b4115eb6924a10beb53da47d463171fe8e63f68207521a4171219bb91d0580bca37b0f96fddeeb8b" , "ea8e6f0935b34e2e6573b89c0856c81b831ef2cadfdee9f44eb9aa0955155ba5e8dd97f85c73f030666846773c91404fb0e12fb38936c56f8cf38a33ac89a24e" , "dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f" , "4fb58702b617ac4f7ca87ec77b93da8a" , "59b2b9dcc7a9a7d089cecf1b83520350" , "3a654de48e8d6b669258b2d33fe6fb179356083eed6ff67e27c5ebfa4d9732bb" , "4e9418436e301a488f675c9508a2d518d8f8f99e966136f2dd7e308b194d74f9" , "c086184486ec6388ff81ec9f23528727" , "c87032009e7c4b2ea27eb6f99723454b" , "c086184486ec6388ff81ec9f235287270429b225" , "6603161719da5e56e1866e4f61f79496334e6a10" , "c086184486ec6388ff81ec9f235287270429b2253b248a70" , "8e914bb64353d4d29ab680e693272d0bd38023afa3943a41" , "76df96157e632410998ad7f823d82930f79a96578acc8ac5ce1bfc34346cf64b4610aefa8a549da3f0c1da36dad314927cebf8ca6f3fcd0649d363c5a370dddb" , "77996016cf6111e97d6ad31484bab1bf7de7b7ee64aebbc243e650a75a2f9256cef104e504d3cf29405888fca5a231fcac85d36cd614b1d52fce850b53ddf7f9" , "0000003f" , "5634cc3b922578434d6e9342ff5913f7" , "aca2a052962b2564027ee62933d2382f" , "22cc5ce1a1ef747cd3fa06106c148dfa" , "469e9cdcaff745460595a7a386c4db0c" , "9ae20f88189f6e3a575b23" , "81f181454e23319779b03d74d062b1a2" , "e44a60f8f2106492ae16581c91edb3ba" , "654741780db415732eaee12b1b909119" , "954ac5505fd1843bbb97d1b2cda0b98f" , "a96103d267d024583d5565436e52dfb3" , "5848c73c2482d3c2c7b6af134ed8dd89" , "8dc71ef37197b2edba02d48c30217b32" , "9032fabd905e273b9ceb1e124631bd67" , "8966f37dbb4aca377a71a9d3d09cd1ac" , "4319a3befce729b34c3105dbc29d0c40" , "ea086739755920e732d0f4d8c1b6ad8d" , "02528c1f2ed8ac7d83fe76f3cf1c133f" , "4548d2c062933dff53928fd4ae427fc0" , "cb4ebaaedfd536d965c452d9569a6b1e" , "099b8a59795e07c334a696a10c0ebce0" , "06e4af76833da7cc138d90602ef80070" , "519de146f1a658ab5e5e2aa9b7d2eec8" , "f006a1863663c21c541c8d600355abfeeaadb5e4" , "299c3d65a0dcab1fc38421783d64d0ecf4113448" , "860465ede0625deebb4fbbedcb0db9dc65faec30" , "6716d047c98c25a9c2cc54ee6134c73e6315a0ff" , "58714327f9407097c64032a2fd5bff3a260cb85f" , "cc600a2903130c945aa178396910135cc7f93c63" , "3de3d8093bf04b8eb5f595bc2da3f37358522c9f" , "00025111b3c4d0ac1635558ce2393f77e94770c5" , "fa960056c0dea57de94776d3759fb555a15cae87" , "1dad2b71432d83312e61d25aeb627593295bcc9a" , "8bceaeed74c17571c15cdb9494e992db3c263695" , "3109b810188fcde0900f9907d2ebcaa10277d10e" , "780d43fa11693b61875321b6b54905ee488d7760" , "5ed6bc680b59c580db4a38df307bd4621759324e" , "70506bac605485b4143ca114cbd4a3580d76a413" , "3328ee2a3b4bf41805bd6aab8e894a992fa91549" , "79f575543061e158c2da3799f999eb7c95261f07")

$alph = "^[a-zA-Z]+$"
$alnum = "^[a-zA-Z0-9]+$"
$digit = "^[0-9]+$"
$version = "1.0"
$banner = @"
_    _           _       _____    _ 
| |  | |         | |     |_   _|  | |
| |__| | __ _ ___| |__     | |  __| |
|  __  |/ _` / __| '_ \    | | / _` |
| |  | | (_| \__ \ | | |  _| || (_| |
|_|  |_|\__,_|___/_| |_| |_____\__,_|
                                     
                                     version = $version
                                     creator = Aynkl
"@

$manual=@"
    Help  : 
        -hash : specify the hash to identify
        -file : specify the file containing the hashes to identify 
        -help : print this manual page
"@
function ADLER32{
    param (
        [String] $hash
    )
    $hs = "0607cb42"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] ADLER-32"
    }
}

function CRC16{
    param (
        [String] $hash
    )
    $hs = "4607"
    if ($hash.Length -eq $hs.Length -and (-not ($hash -match $alph))  -and ($hash -match $alnum)  ){
        Write-Output "[+] CRC-16"
    }
}

function CRC16CCITT{
    param (
        [String] $hash
    )
    $hs = "3d08"
    if ($hash.Length -eq $hs.Length -and (-not ($hash -match $alph)) -and ($hash -match $alnum ) -and (-not( $hash -match $digit))){
        Write-Output "[+] CRC-16-CCITT"
    }
}

function CRC32{
    param (
        [String] $hash
    )
    $hs = "b33fd057"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] CRC-32"
    }
}

function CRC32B{
    param (
        [String] $hash
    )
    $hs = "b764a0d9"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] CRC-328"
    }
}

function DESUnix{
    param (
        [String] $hash
    )
    $hs = "ZiY8YtDKXJwYQ"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] DES(Unix)"
    }
}

function DomainCachedCredentials{
    param (
        [String] $hash
    )
    $hs = "f42005ec1afe77967cbc83dce1b4d714"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Domain Cached Credentials - MD4(MD4((pass)).(strtolower(username)))"
    }
}

function FCS16{
    param (
        [String] $hash
    )
    $hs = "0e5b"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit)) ){
        Write-Output "[+] FCS-16"
    }
}

function GHash323{
    param (
        [String] $hash
    )
    $hs = "80000000"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] GHash-32-3"
    }
}

function GHash325{
    param (
        [String] $hash
    )
    $hs = "85318985"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "GHash-32-5"
    }
}

function GOSTR341194{
    param (
        [String] $hash
    )
    $hs = "ab709d384cce5fda0793becd3da0cb6a926c86a8f3460efb471adddee1c63793"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] GOST R 34.11-94"
    }
}

function Haval128{
    param (
        [String] $hash
    )
    $hs = "d6e3ec49aa0f138a619f27609022df10"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-128"
    }
}

function Haval128HMAC{
    param (
        [String] $hash
    )
    $hs = "3ce8b0ffd75bc240fc7d967729cd6637"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-128(HMAC)"
    }
}

function Haval160{
    param (
        [String] $hash
    )
    $hs = "a106e921284dd69dad06192a4411ec32fce83dbb"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-160"
    }
}

function Haval160HMAC{
    param (
        [String] $hash
    )
    $hs = "29206f83edc1d6c3f680ff11276ec20642881243"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-160(HMAC)"
    }
}

function Haval192{
    param (
        [String] $hash
    )
    $hs = "cd3a90a3bebd3fa6b6797eba5dab8441f16a7dfa96c6e641"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-192"
    }
}

function Haval192HMAC{
    param (
        [String] $hash
    )
    $hs = "39b4d8ecf70534e2fd86bb04a877d01dbf9387e640366029"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-192(HMAC)"
    }
}

function Haval224{
    param (
        [String] $hash
    )
    $hs = "f65d3c0ef6c56f4c74ea884815414c24dbf0195635b550f47eac651a"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-224"
    }
}

function Haval224HMAC{
    param (
        [String] $hash
    )
    $hs = "f10de2518a9f7aed5cf09b455112114d18487f0c894e349c3c76a681"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-224(HMAC)"
    }
}

function Haval256{
    param (
        [String] $hash
    )
    $hs = "7169ecae19a5cd729f6e9574228b8b3c91699175324e6222dec569d4281d4a4a"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-256"
    }
}

function Haval256HMAC{
    param (
        [String] $hash
    )
    $hs = "6aa856a2cfd349fb4ee781749d2d92a1ba2d38866e337a4a1db907654d4d4d7a"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Haval-256(HMAC)"
    }
}

function LineageIIC4{
    param (
        [String] $hash
    )
    $hs = "0x49a57f66bd3d5ba6abda5579c264a0e4"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Lineage II C4"
    }
}

function MD2{
    param (
        [String] $hash
    )
    $hs = "08bbef4754d98806c373f2cd7d9a43c4"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD2"
    }
}

function MD2HMAC{
    param (
        [String] $hash
    )
    $hs = "4b61b72ead2b0eb0fa3b8a56556a6dca"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD2(HMAC)"
    }
}

function MD4{
    param (
        [String] $hash
    )
    $hs = "a2acde400e61410e79dacbdfc3413151"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD4"
    }
}

function MD4HMAC{
    param (
        [String] $hash
    )
    $hs = "6be20b66f2211fe937294c1c95d1cd4f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD4(HMAC)"
    }
}

function MD5{
    param (
        [String] $hash
    )
    $hs = "ae11fd697ec92c7c98de3fac23aba525"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5"
    }
}

function MD5APR{
    param (
        [String] $hash
    )
    $hs = '$apr1$qAUKoKlG$3LuCncByN76eLxZAh/Ldr1'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(APR)"
    }
}

function MD5HMAC{
    param (
        [String] $hash
    )
    $hs = "d57e43d2c7e397bf788f66541d6fdef9"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(HMAC)"
    }
}

function MD5HMACWordpress{
    param (
        [String] $hash
    )
    $hs = "3f47886719268dfa83468630948228f6"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(HMAC(Wordpress))"
    }
}

function MD5phpBB3{
    param (
        [String] $hash
    )
    $hs ='$H$9kyOtE8CDqMJ44yfn9PFz2E.L2oVzL1'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(phpBB3)"
    }
}

function MD5Unix{
    param (
        [String] $hash
    )
    $hs = '$1$cTuJH0Ju$1J8rI.mJReeMvpKUZbSlY/'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(Unix)"
    }
}

function MD5Wordpress{
    param (
        [String] $hash
    )
    $hs = '$P$BiTOhOj3ukMgCci2juN0HRbCdDRqeh.'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(Wordpress)"
    }
}

function MD5Half{
    param (
        [String] $hash
    )
    $hs = "ae11fd697ec92c7c"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(Half)"
    }
}

function MD5Middle{
    param (
        [String] $hash
    )
    $hs = "7ec92c7c98de3fac"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MD5(Middle)"
    }
}

function MD5passsaltjoomla1{
    param (
        [String] $hash
    )
    $hs = '35d1c0d69a2df62be2df13b087343dc9:BeKMviAfcXeTPTlX'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(pass.salt) - Joomla"
    }
}

function MD5passsaltjoomla2{
    param (
        [String] $hash
    )
    $hs = 'fb33e01e4f8787dc8beb93dac4107209:fxJUXVjYRafVauT77Cze8XwFrWaeAYB2'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(pass.salt) - Joomla"
    }
}

function MySQL{
    param (
        [String] $hash
    )
    $hs = "63cea4673fd25f46"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MySQL"
    }
}

function MySQL5{
    param (
        [String] $hash
    )
    $hs = "9bb2fb57063821c762cc009f7584ddae9da431ff"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MySQL5 - SHA-1(SHA-1(pass))"
    }
}

function MySQL160bit{
    param (
        [String] $hash
    )
    $hs = "2470c0c06dee42fd1618bb99005adca2ec9d1e19"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] MySQL 160bit - SHA-1(SHA-1(pass))"
    }
}

function NTLM{
    param (
        [String] $hash
    )
    $hs = "cc348bace876ea440a28ddaeb9fd3550"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] NTLM"
    }
}

function RAdminv2x{
    param (
        [String] $hash
    )
    $hs = "baea31c728cbf0cd548476aa687add4b"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RAdmin v2.x"
    }
}

function RipeMD128{
    param (
        [String] $hash
    )
    $hs = "4985351cd74aff0abc5a75a0c8a54115"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] ipeMD-128"
    }
}

function RipeMD128HMAC{
    param (
        [String] $hash
    )
    $hs = "ae1995b931cf4cbcf1ac6fbf1a83d1d3"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-128(HMAC)"
    }
}

function RipeMD160{
    param (
        [String] $hash
    )
    $hs = "dc65552812c66997ea7320ddfb51f5625d74721b"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-160"
    }
}

function RipeMD160HMAC{
    param (
        [String] $hash
    )
    $hs = "ca28af47653b4f21e96c1235984cb50229331359"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-160(HMAC)"
    }
}

function RipeMD256{
    param (
        [String] $hash
    )
    $hs = '5fcbe06df20ce8ee16e92542e591bdea706fbdc2442aecbf42c223f4461a12af'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-256"
    }
}

function RipeMD256HMAC{
    param (
        [String] $hash
    )
    $hs = "43227322be1b8d743e004c628e0042184f1288f27c13155412f08beeee0e54bf"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-256(HMAC)"
    }
}

function RipeMD320{
    param (
        [String] $hash
    )
    $hs = "b4f7c8993a389eac4f421b9b3b2bfb3a241d05949324a8dab1286069a18de69aaf5ecc3c2009d8ef"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-320"
    }
}

function RipeMD320HMAC{
    param (
        [String] $hash
    )
    $hs = "244516688f8ad7dd625836c0d0bfc3a888854f7c0161f01de81351f61e98807dcd55b39ffe5d7a78"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] RipeMD-320(HMAC)"
    }
}

function SAM{
    param (
        [String] $hash
    )
    $hs = "4318B176C3D8E3DEAAD3B435B51404EE:B7C899154197E8A2A33121D76A240AB5"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SAM - (LM_hash:NT_hash)"
    }
}

function SHA1{
    param (
        [String] $hash
    )
    $hs = "4a1d4dbc1e193ec3ab2e9213876ceb8f4db72333"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-1"
    }
}

function SHA1Django{
    param (
        [String] $hash
    )
    $hs = 'sha1$Zion3R$299c3d65a0dcab1fc38421783d64d0ecf4113448'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-1(Django)"
    }
}

function SHA1HMAC{
    param (
        [String] $hash
    )
    $hs = "6f5daac3fee96ba1382a09b1ba326ca73dccf9e7"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-1(HMAC)"
    }
}

function SHA1MaNGOS{
    param (
        [String] $hash
    )
    $hs = "a2c0cdb6d1ebd1b9f85c6e25e0f8732e88f02f96"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-1(MaNGOS)"
    }
}

function SHA1MaNGOS2{
    param (
        [String] $hash
    )
    $hs = "644a29679136e09d0bd99dfd9e8c5be84108b5fd"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-1(MaNGOS2)"
    }
}

function SHA224{
    param (
        [String] $hash
    )
    $hs = "e301f414993d5ec2bd1d780688d37fe41512f8b57f6923d054ef8e59"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-224"
    }
}

function SHA224HMAC{
    param (
        [String] $hash
    )
    $hs = "c15ff86a859892b5e95cdfd50af17d05268824a6c9caaa54e4bf1514"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-224(HMAC)"
    }
}

function SHA256{
    param (
        [String] $hash
    )
    $hs = "2c740d20dab7f14ec30510a11f8fd78b82bc3a711abe8a993acdb323e78e6d5e"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-256"
    }
}

function SHA256s{
    param (
        [String] $hash
    )
    $hs = '$6$g4TpUQzk$OmsZBJFwvy6MwZckPvVYfDnwsgktm2CckOlNJGy9HNwHSuHFvywGIuwkJ6Bjn3kKbB6zoyEjIYNMpHWBNxJ6g.'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-256"
    }
}

function SHA256Django{
    param (
        [String] $hash
    )
    $hs = 'sha256$Zion3R$9e1a08aa28a22dfff722fad7517bae68a55444bb5e2f909d340767cec9acf2c3'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-256(Django)"
    }
}

function SHA256HMAC{
    param (
        [String] $hash
    )
    $hs = "d3dd251b7668b8b6c12e639c681e88f2c9b81105ef41caccb25fcde7673a1132"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-256(HMAC)"
    }
}

function SHA256md5pass{
    param (
        [String] $hash
    )
    $hs = "b419557099cfa18a86d1d693e2b3b3e979e7a5aba361d9c4ec585a1a70c7bde4"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-256(md5(pass))"
    }
}

function SHA256sha1pass{
    param (
        [String] $hash
    )
    $hs = "afbed6e0c79338dbfe0000efe6b8e74e3b7121fe73c383ae22f5b505cb39c886"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-256(sha1(pass))"
    }
}

function SHA384{
    param (
        [String] $hash
    )
    $hs = "3b21c44f8d830fa55ee9328a7713c6aad548fe6d7a4a438723a0da67c48c485220081a2fbc3e8c17fd9bd65f8d4b4e6b"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-384"
    }
}

function SHA384Django{
    param (
        [String] $hash
    )
    $hs = 'sha384$Zion3R$88cfd5bc332a4af9f09aa33a1593f24eddc01de00b84395765193c3887f4deac46dc723ac14ddeb4d3a9b958816b7bba'
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-384(Django)"
    }
}

function SHA384HMAC{
    param (
        [String] $hash
    )
    $hs = "bef0dd791e814d28b4115eb6924a10beb53da47d463171fe8e63f68207521a4171219bb91d0580bca37b0f96fddeeb8b"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-384(HMAC)"
    }
}

function SHA512{
    param (
        [String] $hash
    )
    $hs = "ea8e6f0935b34e2e6573b89c0856c81b831ef2cadfdee9f44eb9aa0955155ba5e8dd97f85c73f030666846773c91404fb0e12fb38936c56f8cf38a33ac89a24e"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-512"
    }
}

function SHA512HMAC{
    param (
        [String] $hash
    )
    $hs = "dd0ada8693250b31d9f44f3ec2d4a106003a6ce67eaa92e384b356d1b4ef6d66a818d47c1f3a2c6e8a9a9b9bdbd28d485e06161ccd0f528c8bbb5541c3fef36f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SHA-512(HMAC)"
    }
}



function SNEFRU128{
    param (
        [String] $hash
    )
    $hs = "4fb58702b617ac4f7ca87ec77b93da8a"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SNEFRU-128"
    }
}

function SNEFRU128HMAC{
    param (
        [String] $hash
    )
    $hs = "59b2b9dcc7a9a7d089cecf1b83520350"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SNEFRU-128(HMAC)"
    }
}

function SNEFRU256{
    param (
        [String] $hash
    )
    $hs = "3a654de48e8d6b669258b2d33fe6fb179356083eed6ff67e27c5ebfa4d9732bb"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SNEFRU-256"
    }
}

function SNEFRU256HMAC{
    param (
        [String] $hash
    )
    $hs = "4e9418436e301a488f675c9508a2d518d8f8f99e966136f2dd7e308b194d74f9"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] SNEFRU-256(HMAC)"
    }
}

function Tiger128{
    param (
        [String] $hash
    )
    $hs = "c086184486ec6388ff81ec9f23528727"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Tiger-128"
    }
}

function Tiger128HMAC{
    param (
        [String] $hash
    )
    $hs = "c87032009e7c4b2ea27eb6f99723454b"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Tiger-128(HMAC)"
    }
}

function Tiger160{
    param (
        [String] $hash
    )
    $hs = "c086184486ec6388ff81ec9f235287270429b225"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Tiger-160"
    }
}

function Tiger160HMAC{
    param (
        [String] $hash
    )
    $hs = "6603161719da5e56e1866e4f61f79496334e6a10"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Tiger-160(HMAC)"
    }
}

function Tiger192{
    param (
        [String] $hash
    )
    $hs = "c086184486ec6388ff81ec9f235287270429b2253b248a70"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Tiger-192"
    }
}

function Tiger192HMAC{
    param (
        [String] $hash
    )
    $hs = "8e914bb64353d4d29ab680e693272d0bd38023afa3943a41"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Tiger-192(HMAC)"
    }
}

function Whirlpool{
    param (
        [String] $hash
    )
    $hs = "76df96157e632410998ad7f823d82930f79a96578acc8ac5ce1bfc34346cf64b4610aefa8a549da3f0c1da36dad314927cebf8ca6f3fcd0649d363c5a370dddb"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Whirlpool"
    }
}

function WhirlpoolHMAC{
    param (
        [String] $hash
    )
    $hs = "77996016cf6111e97d6ad31484bab1bf7de7b7ee64aebbc243e650a75a2f9256cef104e504d3cf29405888fca5a231fcac85d36cd614b1d52fce850b53ddf7f9"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] Whirlpool(HMAC)"
    }
}

function XOR32{
    param (
        [String] $hash
    )
    $hs = "0000003f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] XOR-32"
    }
}

function md5passsalt{
    param (
        [String] $hash
    )
    $hs = "5634cc3b922578434d6e9342ff5913f7"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(pass.salt)"
    }
}

function md5saltmd5pass{
    param (
        [String] $hash
    )
    $hs = "aca2a052962b2564027ee62933d2382f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.md5(pass))"
    }
}

function md5saltpass{
    param (
        [String] $hash
    )
    $hs = "22cc5ce1a1ef747cd3fa06106c148dfa"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.pass)"
    }
}

function md5saltpasssalt{
    param (
        [String] $hash
    )
    $hs = "469e9cdcaff745460595a7a386c4db0c"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.pass.salt)"
    }
}

function md5saltpassusername{
    param (
        [String] $hash
    )
    $hs = "9ae20f88189f6e3a62711608ddb6f5fd"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.pass.username)"
    }
}

function md5saltmd5pass{
    param (
        [String] $hash
    )
    $hs = "aca2a052962b2564027ee62933d2382f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.md5(pass))"
    }
}

function md5saltmd5passsalt{
    param (
        [String] $hash
    )
    $hs = "5b8b12ca69d3e7b2a3e2308e7bef3e6f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.md5(pass.salt))"
    }
}

function md5saltmd5saltpass{
    param (
        [String] $hash
    )
    $hs = "d8f3b3f004d387086aae24326b575b23"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.md5(salt.pass))"
    }
}

function md5saltmd5md5passsalt{
    param (
        [String] $hash
    )
    $hs = "81f181454e23319779b03d74d062b1a2"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(salt.md5(md5(pass).salt))"
    }
}

function md5username0pass{
    param (
        [String] $hash
    )
    $hs = "e44a60f8f2106492ae16581c91edb3ba"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(username.0.pass)"
    }
}

function md5usernameLFpass{
    param (
        [String] $hash
    )
    $hs = "654741780db415732eaee12b1b909119"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(username.LF.pass)"
    }
}

function md5usernamemd5passsalt{
    param (
        [String] $hash
    )
    $hs = "954ac5505fd1843bbb97d1b2cda0b98f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(username.md5(pass).salt)"
    }
}

function md5md5pass{
    param (
        [String] $hash
    )
    $hs = "a96103d267d024583d5565436e52dfb3"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(pass))"
    }
}

function md5md5passsalt{
    param (
        [String] $hash
    )
    $hs = "5848c73c2482d3c2c7b6af134ed8dd89"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(pass).salt)"
    }
}


function md5md5passmd5salt{
    param (
        [String] $hash
    )
    $hs = "8dc71ef37197b2edba02d48c30217b32"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(pass).md5(salt))"
    }
}

function md5md5saltpass{
    param (
        [String] $hash
    )
    $hs = "9032fabd905e273b9ceb1e124631bd67"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(salt).pass)"
    }
}

function md5md5saltmd5pass{
    param (
        [String] $hash
    )
    $hs = "8966f37dbb4aca377a71a9d3d09cd1ac"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(salt).md5(pass))"
    }
}

function md5md5usernamepasssalt{
    param (
        [String] $hash
    )
    $hs = "4319a3befce729b34c3105dbc29d0c40"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(username.pass).salt)"
    }
}

function md5md5md5pass{
    param (
        [String] $hash
    )
    $hs = "ea086739755920e732d0f4d8c1b6ad8d"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(md5(pass)))"
    }
}

function md5md5md5md5pass{
    param (
        [String] $hash
    )
    $hs = "02528c1f2ed8ac7d83fe76f3cf1c133f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(md5(md5(pass))))"
    }
}

function md5md5md5md5md5pass{
    param (
        [String] $hash
    )
    $hs = "4548d2c062933dff53928fd4ae427fc0"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(md5(md5(md5(md5(pass)))))"
    }
}

function md5sha1pass{
    param (
        [String] $hash
    )
    $hs = "cb4ebaaedfd536d965c452d9569a6b1e"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(sha1(pass))"
    }
}

function md5sha1md5pass{
    param (
        [String] $hash
    )
    $hs = "099b8a59795e07c334a696a10c0ebce0"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(sha1(md5(pass)))"
    }
}

function md5sha1md5sha1pass{
    param (
        [String] $hash
    )
    $hs = "06e4af76833da7cc138d90602ef80070"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(sha1(md5(sha1(pass))))"
    }
}

function md5strtouppermd5pass{
    param (
        [String] $hash
    )
    $hs = "519de146f1a658ab5e5e2aa9b7d2eec8"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] md5(strtoupper(md5(pass)))"
    }
}

function sha1passsalt{
    param (
        [String] $hash
    )
    $hs = "f006a1863663c21c541c8d600355abfeeaadb5e4"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(pass.salt)"
    }
}

function sha1saltpass{
    param (
        [String] $hash
    )
    $hs = "299c3d65a0dcab1fc38421783d64d0ecf4113448"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(salt.pass)"
    }
}

function sha1saltmd5pass{
    param (
        [String] $hash
    )
    $hs = "860465ede0625deebb4fbbedcb0db9dc65faec30"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(salt.md5(pass))"
    }
}

function sha1saltmd5passsalt{
    param (
        [String] $hash
    )
    $hs = "6716d047c98c25a9c2cc54ee6134c73e6315a0ff"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(salt.md5(pass).salt)"
    }
}

function sha1saltsha1pass{
    param (
        [String] $hash
    )
    $hs = "58714327f9407097c64032a2fd5bff3a260cb85f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(salt.sha1(pass))"
    }
}

function sha1saltsha1saltsha1pass{
    param (
        [String] $hash
    )
    $hs = "cc600a2903130c945aa178396910135cc7f93c63"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(salt.sha1(salt.sha1(pass)))"
    }
}

function sha1usernamepass{
    param (
        [String] $hash
    )
    $hs = "3de3d8093bf04b8eb5f595bc2da3f37358522c9f"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(username.pass)"
    }
}

function sha1usernamepasssalt{
    param (
        [String] $hash
    )
    $hs = "00025111b3c4d0ac1635558ce2393f77e94770c5"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(username.pass.salt)"
    }
}

function sha1md5pass{
    param (
        [String] $hash
    )
    $hs = "fa960056c0dea57de94776d3759fb555a15cae87"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(md5(pass))"
    }
}

function sha1md5passsalt{
    param (
        [String] $hash
    )
    $hs = "1dad2b71432d83312e61d25aeb627593295bcc9a"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(md5(pass).salt)"
    }
}

function sha1md5sha1pass{
    param (
        [String] $hash
    )
    $hs = "8bceaeed74c17571c15cdb9494e992db3c263695"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(md5(sha1(pass)))"
    }
}

function sha1sha1pass{
    param (
        [String] $hash
    )
    $hs = "3109b810188fcde0900f9907d2ebcaa10277d10e"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(sha1(pass))"
    }
}

function sha1sha1passsalt{
    param (
        [String] $hash
    )
    $hs = "780d43fa11693b61875321b6b54905ee488d7760"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(sha1(pass).salt)"
    }
}

function sha1sha1passsubstrpass03{
    param (
        [String] $hash
    )
    $hs = "5ed6bc680b59c580db4a38df307bd4621759324e"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(sha1(pass).substr(pass,0,3))"
    }
}

function sha1sha1saltpass{
    param (
        [String] $hash
    )
    $hs = "70506bac605485b4143ca114cbd4a3580d76a413"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(sha1(salt.pass))"
    }
}

function sha1sha1sha1pass{
    param (
        [String] $hash
    )
    $hs = "3328ee2a3b4bf41805bd6aab8e894a992fa91549"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(sha1(sha1(pass)))"
    }
}

function sha1strtolowerusernamepass{
    param (
        [String] $hash
    )
    $hs = "79f575543061e158c2da3799f999eb7c95261f07"
    if ($hash.Length -eq $hs.Length -and (-not( $hash -match $alph))  -and ($hash -match $alnum) -and (-not ($hash -match $digit))  ){
        Write-Output "[+] sha1(strtolower(username).pass)"
    }
}
function Get-HashId {

    param (
        [Parameter(Mandatory=$false)][string]$hash,
        [Parameter(Mandatory=$false)][string]$file,
        [Parameter(Mandatory=$false)][switch]$help
        )
    Clear-Host
    Write-Host $banner
    if ($help) {
        Write-Host $manual
    }
    if ( $hash.Length -ne 0 -and $file.Length -ne 0 ){
        Write-Error -Message "Can't input both hash and file"
    }elseif ($file.Length -ne 0) {
        $hash = Get-Content $file 
    }
    ADLER32($hash)
    CRC16($hash)
    CRC16CCITT($hash)
    CRC32($hash)
    CRC32B($hash)
    DESUnix($hash)
    DomainCachedCredentials($hash)
    FCS16($hash)
    GHash323($hash)
    GHash325($hash)
    GOSTR341194($hash)
    Haval128($hash)
    Haval128HMAC($hash)
    Haval160($hash)
    Haval160HMAC($hash)
    Haval192($hash)
    Haval192HMAC($hash)
    Haval224($hash)
    Haval224HMAC($hash)
    Haval256($hash)
    Haval256HMAC($hash)
    LineageIIC4($hash)
    MD2($hash)
    MD2HMAC($hash)
    MD4($hash)
    MD4HMAC($hash)
    MD5($hash)
    MD5APR($hash)
    MD5HMAC($hash)
    MD5HMACWordpress($hash)
    MD5phpBB3($hash)
    MD5Unix($hash)
    MD5Wordpress($hash)
    MD5Half($hash)
    MD5Middle($hash)
    MD5passsaltjoomla1($hash)
    MD5passsaltjoomla2($hash)
    MySQL($hash)
    MySQL5($hash)
    MySQL160bit($hash)
    NTLM($hash)
    RAdminv2x($hash)
    RipeMD128($hash)
    RipeMD128HMAC($hash)
    RipeMD160($hash)
    RipeMD160HMAC($hash)
    RipeMD256($hash)
    RipeMD256HMAC($hash)
    RipeMD320($hash)
    RipeMD320HMAC($hash)
    SAM($hash)
    SHA1($hash)
    SHA1Django($hash)
    SHA1HMAC($hash)
    SHA1MaNGOS($hash)
    SHA1MaNGOS2($hash)
    SHA224($hash)
    SHA224HMAC($hash)
    SHA256($hash)
    SHA256s($hash)
    SHA256Django($hash)
    SHA256HMAC($hash)
    SHA256md5pass($hash)
    SHA256sha1pass($hash)
    SHA384($hash)
    SHA384Django($hash)
    SHA384HMAC($hash)
    SHA512($hash)
    SHA512HMAC($hash)
    SNEFRU128($hash)
    SNEFRU128HMAC($hash)
    SNEFRU256($hash)
    SNEFRU256HMAC($hash)
    Tiger128($hash)
    Tiger128HMAC($hash)
    Tiger160($hash)
    Tiger160HMAC($hash)
    Tiger192($hash)
    Tiger192HMAC($hash)
    Whirlpool($hash)
    WhirlpoolHMAC($hash)
    XOR32($hash)
    md5passsalt($hash)
    md5saltmd5pass($hash)
    md5saltpass($hash)
    md5saltpasssalt($hash)
    md5saltpassusername($hash)
    md5saltmd5pass($hash)
    md5saltmd5passsalt($hash)
    md5saltmd5saltpass($hash)
    md5saltmd5md5passsalt($hash)
    md5username0pass($hash)
    md5usernameLFpass($hash)
    md5usernamemd5passsalt($hash)
    md5md5pass($hash)
    md5md5passsalt($hash)
    md5md5passmd5salt($hash)
    md5md5saltpass($hash)
    md5md5saltmd5pass($hash)
    md5md5usernamepasssalt($hash)
    md5md5md5pass($hash)
    md5md5md5md5pass($hash)
    md5md5md5md5md5pass($hash)
    md5sha1pass($hash)
    md5sha1md5pass($hash)
    md5sha1md5sha1pass($hash)
    md5strtouppermd5pass($hash)
    sha1passsalt($hash)
    sha1saltpass($hash)
    sha1saltmd5pass($hash)
    sha1saltmd5passsalt($hash)
    sha1saltsha1pass($hash)
    sha1saltsha1saltsha1pass($hash)
    sha1usernamepass($hash)
    sha1usernamepasssalt($hash)
    sha1md5pass($hash)
    sha1md5passsalt($hash)
    sha1md5sha1pass($hash)
    sha1sha1pass($hash)
    sha1sha1passsalt($hash)
    sha1sha1passsubstrpass03($hash)
    sha1sha1saltpass($hash)
    sha1sha1sha1pass($hash)
    sha1strtolowerusernamepass($hash)
}
# Get-HashId  -hash "4607"