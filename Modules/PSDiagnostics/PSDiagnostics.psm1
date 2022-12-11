# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
  PowerShell Diagnostics Module
  This module contains a set of wrapper scripts that
  enable a user to use ETW tracing in Windows
  PowerShell.
 #>

$script:Logman="$env:windir\system32\logman.exe"
$script:wsmanlogfile = "$env:windir\system32\wsmtraces.log"
$script:wsmprovfile = "$env:windir\system32\wsmtraceproviders.txt"
$script:wsmsession = "wsmlog"
$script:pssession = "PSTrace"
$script:psprovidername="Microsoft-Windows-PowerShell"
$script:wsmprovidername = "Microsoft-Windows-WinRM"
$script:oplog = "/Operational"
$script:analyticlog="/Analytic"
$script:debuglog="/Debug"
$script:wevtutil="$env:windir\system32\wevtutil.exe"
$script:slparam = "sl"
$script:glparam = "gl"

function Start-Trace
{
    Param(
    [Parameter(Mandatory=$true,
               Position=0)]
    [string]
    $SessionName,
    [Parameter(Position=1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $OutputFilePath,
    [Parameter(Position=2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ProviderFilePath,
    [Parameter()]
    [Switch]
    $ETS,
    [Parameter()]
    [ValidateSet("bin", "bincirc", "csv", "tsv", "sql")]
    $Format,
    [Parameter()]
    [int]
    $MinBuffers=0,
    [Parameter()]
    [int]
    $MaxBuffers=256,
    [Parameter()]
    [int]
    $BufferSizeInKB = 0,
    [Parameter()]
    [int]
    $MaxLogFileSizeInMB=0
    )

    Process
    {
        $executestring = " start $SessionName"

        if ($ETS)
        {
            $executestring += " -ets"
        }

        if ($null -ne $OutputFilePath)
        {
            $executestring += " -o ""$OutputFilePath"""
        }

        if ($null -ne $ProviderFilePath)
        {
            $executestring += " -pf ""$ProviderFilePath"""
        }

        if ($null -ne $Format)
        {
            $executestring += " -f $Format"
        }

        if ($MinBuffers -ne 0 -or $MaxBuffers -ne 256)
        {
            $executestring += " -nb $MinBuffers $MaxBuffers"
        }

        if ($BufferSizeInKB -ne 0)
        {
            $executestring += " -bs $BufferSizeInKB"
        }

        if ($MaxLogFileSizeInMB -ne 0)
        {
            $executestring += " -max $MaxLogFileSizeInMB"
        }

        & $script:Logman $executestring.Split(" ")
    }
}

function Stop-Trace
{
    param(
    [Parameter(Mandatory=$true,
               Position=0)]
    $SessionName,
    [Parameter()]
    [switch]
    $ETS
    )

    Process
    {
        if ($ETS)
        {
            & $script:Logman update $SessionName -ets
            & $script:Logman stop $SessionName -ets
        }
        else
        {
            & $script:Logman update $SessionName
            & $script:Logman stop $SessionName
        }
    }
}

function Enable-WSManTrace
{

    # winrm
    "{04c6e16d-b99f-4a3a-9b3e-b8325bbc781e} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii

    # winrsmgr
    "{c0a36be8-a515-4cfa-b2b6-2676366efff7} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    # WinrsExe
    "{f1cab2c0-8beb-4fa2-90e1-8f17e0acdd5d} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    # WinrsCmd
    "{03992646-3dfe-4477-80e3-85936ace7abb} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    # IPMIPrv
    "{651d672b-e11f-41b7-add3-c2f6a4023672} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    #IpmiDrv
    "{D5C6A3E9-FA9C-434e-9653-165B4FC869E4} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    # WSManProvHost
    "{6e1b64d7-d3be-4651-90fb-3583af89d7f1} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    # Event Forwarding
    "{6FCDF39A-EF67-483D-A661-76D715C6B008} 0xffffffff 0xff" | Out-File $script:wsmprovfile -Encoding ascii -Append

    Start-Trace -SessionName $script:wsmsession -ETS -OutputFilePath $script:wsmanlogfile -Format bincirc -MinBuffers 16 -MaxBuffers 256 -BufferSizeInKB 64 -MaxLogFileSizeInMB 256 -ProviderFilePath $script:wsmprovfile
}

function Disable-WSManTrace
{
    Stop-Trace $script:wsmsession -ETS
}

function Enable-PSWSManCombinedTrace
{
    param (
        [switch] $DoNotOverwriteExistingTrace
    )

    $provfile = [io.path]::GetTempFilename()

    $traceFileName = [string][Guid]::NewGuid()
    if ($DoNotOverwriteExistingTrace) {
        $fileName = [string][guid]::newguid()
        $logfile = $PSHOME + "\\Traces\\PSTrace_$fileName.etl"
    } else {
        $logfile = $PSHOME + "\\Traces\\PSTrace.etl"
    }

    "Microsoft-Windows-PowerShell 0 5" | Out-File $provfile -Encoding ascii
    "Microsoft-Windows-WinRM 0 5" | Out-File $provfile -Encoding ascii -Append

    if (!(Test-Path $PSHOME\Traces))
    {
        New-Item -ItemType Directory -Force $PSHOME\Traces | Out-Null
    }

    if (Test-Path $logfile)
    {
        Remove-Item -Force $logfile | Out-Null
    }

    Start-Trace -SessionName $script:pssession -OutputFilePath $logfile -ProviderFilePath $provfile -ETS

    Remove-Item $provfile -Force -ea 0
}

function Disable-PSWSManCombinedTrace
{
    Stop-Trace -SessionName $script:pssession -ETS
}

function Set-LogProperties
{
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Microsoft.PowerShell.Diagnostics.LogDetails]
        $LogDetails,
        [switch] $Force
     )

    Process
    {
        if ($LogDetails.AutoBackup -and !$LogDetails.Retention)
        {
            throw (New-Object System.InvalidOperationException)
        }

        $enabled = $LogDetails.Enabled.ToString()
        $retention = $LogDetails.Retention.ToString()
        $autobackup = $LogDetails.AutoBackup.ToString()
        $maxLogSize = $LogDetails.MaxLogSize.ToString()
        $osVersion = [Version] (Get-CimInstance Win32_OperatingSystem).Version

        if (($LogDetails.Type -eq "Analytic") -or ($LogDetails.Type -eq "Debug"))
        {
            if ($LogDetails.Enabled)
            {
                if($osVersion -lt 6.3.7600)
                {
                    & $script:wevtutil $script:slparam $LogDetails.Name -e:$Enabled
                }
                else
                {
                    & $script:wevtutil /q:$Force $script:slparam $LogDetails.Name -e:$Enabled
                }
            }
            else
            {
                if($osVersion -lt 6.3.7600)
                {
                    & $script:wevtutil $script:slparam $LogDetails.Name -e:$Enabled -rt:$Retention -ms:$MaxLogSize
                }
                else
                {
                    & $script:wevtutil /q:$Force $script:slparam $LogDetails.Name -e:$Enabled -rt:$Retention -ms:$MaxLogSize
                }
            }
        }
        else
        {
            if($osVersion -lt 6.3.7600)
            {
                & $script:wevtutil $script:slparam $LogDetails.Name -e:$Enabled -rt:$Retention -ab:$AutoBackup -ms:$MaxLogSize
            }
            else
            {
                & $script:wevtutil /q:$Force $script:slparam $LogDetails.Name -e:$Enabled -rt:$Retention -ab:$AutoBackup -ms:$MaxLogSize
            }
        }
    }
}

function ConvertTo-Bool([string]$value)
{
    if ($value -ieq "true")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function Get-LogProperties
{
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)] $Name
    )

    Process
    {
        $details = & $script:wevtutil $script:glparam $Name
        $indexes = @(1,2,8,9,10)
        $value = @()
        foreach($index in $indexes)
        {
            $value += @(($details[$index].SubString($details[$index].IndexOf(":")+1)).Trim())
        }

        $enabled = ConvertTo-Bool $value[0]
        $retention = ConvertTo-Bool $value[2]
        $autobackup = ConvertTo-Bool $value[3]

        New-Object Microsoft.PowerShell.Diagnostics.LogDetails $Name, $enabled, $value[1], $retention, $autobackup, $value[4]
    }
}

function Enable-PSTrace
{
    param(
        [switch] $Force,
		[switch] $AnalyticOnly
     )

    $Properties = Get-LogProperties ($script:psprovidername + $script:analyticlog)

	if (!$Properties.Enabled) {
		$Properties.Enabled = $true
		if ($Force) {
			Set-LogProperties $Properties -Force
		} else {
			Set-LogProperties $Properties
		}
	}

	if (!$AnalyticOnly) {
		$Properties = Get-LogProperties ($script:psprovidername + $script:debuglog)
		if (!$Properties.Enabled) {
			$Properties.Enabled = $true
			if ($Force) {
				Set-LogProperties $Properties -Force
			} else {
				Set-LogProperties $Properties
			}
		}
	}
}

function Disable-PSTrace
{
    param(
		[switch] $AnalyticOnly
     )
    $Properties = Get-LogProperties ($script:psprovidername + $script:analyticlog)
	if ($Properties.Enabled) {
		$Properties.Enabled = $false
		Set-LogProperties $Properties
	}

	if (!$AnalyticOnly) {
		$Properties = Get-LogProperties ($script:psprovidername + $script:debuglog)
		if ($Properties.Enabled) {
			$Properties.Enabled = $false
			Set-LogProperties $Properties
		}
	}
}
Add-Type @"
using System;

namespace Microsoft.PowerShell.Diagnostics
{
    public class LogDetails
    {
        public string Name
        {
            get
            {
                return name;
            }
        }
        private string name;

        public bool Enabled
        {
            get
            {
                return enabled;
            }
            set
            {
                enabled = value;
            }
        }
        private bool enabled;

        public string Type
        {
            get
            {
                return type;
            }
        }
        private string type;

        public bool Retention
        {
            get
            {
                return retention;
            }
            set
            {
                retention = value;
            }
        }
        private bool retention;

        public bool AutoBackup
        {
            get
            {
                return autoBackup;
            }
            set
            {
                autoBackup = value;
            }
        }
        private bool autoBackup;

        public int MaxLogSize
        {
            get
            {
                return maxLogSize;
            }
            set
            {
                maxLogSize = value;
            }
        }
        private int maxLogSize;

        public LogDetails(string name, bool enabled, string type, bool retention, bool autoBackup, int maxLogSize)
        {
            this.name = name;
            this.enabled = enabled;
            this.type = type;
            this.retention = retention;
            this.autoBackup = autoBackup;
            this.maxLogSize = maxLogSize;
        }
    }
}
"@

if (Get-Command logman.exe -Type Application -ErrorAction SilentlyContinue)
{
    Export-ModuleMember Disable-PSTrace, Disable-PSWSManCombinedTrace, Disable-WSManTrace, Enable-PSTrace, Enable-PSWSManCombinedTrace, Enable-WSManTrace, Get-LogProperties, Set-LogProperties, Start-Trace, Stop-Trace
}
else
{
    # Currently we only support these cmdlets as logman.exe is not available on systems like Nano and IoT
    Export-ModuleMember Disable-PSTrace, Enable-PSTrace, Get-LogProperties, Set-LogProperties
}

# SIG # Begin signature block
# MIInoAYJKoZIhvcNAQcCoIInkTCCJ40CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBzuFp8c8UN6ilP
# /hSmUPDtAUbo8uWTs6wUbaR/ZpM1B6CCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZdTCCGXECAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgSB3jjVY/
# WMZ8WHFGDewy2JQLkkMsgxe7OQ9hGxl1POAwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCNs2MTNymhtdaw/FeKCxb9mxIJyxCIko/mvuu624eH
# Sz3ZPJI1k363kHS8K3zXPzHbfI6SzzHskB627WhG96/+1K6jzhOlEp2cyBAfb2BW
# OOidosfUO4FxBa0YNWgUWJ13zqSXxM97P5NDQOqOFhLlzTuhQMoVIUYrMh9FDP+h
# e0sZdzsI+ztks+1kRViadTSHMqgr8dzhQ5jyn2pB43TqImcm3IcNj30TbjA3iIE6
# S2UorEZ3ow86SaMNow/eD2AoQyrJktRQQg6z4AhMmPfA2Nm5Kti83SuG40cbvFFk
# yfvpwH0rwubBMALddxGo60LbuonGNUN3F9c0o0z4BR0/oYIW/zCCFvsGCisGAQQB
# gjcDAwExghbrMIIW5wYJKoZIhvcNAQcCoIIW2DCCFtQCAQMxDzANBglghkgBZQME
# AgEFADCCAVAGCyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIBcdQSTVvCC/B+d+bSXaMVP+6DY/HmlcGtOBBG0k
# pwATAgZjSDYxV+4YEjIwMjIxMDE4MDAwOTIxLjA2WjAEgAIB9KCB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RTVBNi1FMjdDLTU5MkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFXMIIHDDCCBPSgAwIBAgITMwAAAZW3/A3W4zcxJQABAAABlTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEyMDIxOTA1MTJaFw0yMzAyMjgxOTA1MTJaMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFNUE2LUUyN0MtNTky
# RTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJ9tQQxntks7P1qhEJ4kviGFP1DwlkHb
# FpWUw0K3dvCFxMjkYs+u3Z73cMCyaWo7PDVwWI8+DpLmwsJfPstttRCkuFrxLi/a
# pxwy1OiQRoNBL5AkSucCyXpVKZG8DLSeWP4L89pm4tvc7NjQBHDtR4JkunJY88f6
# Tkx1iPo1QNM2hepvNAcK4+z5+AiiujnLcMeg7TvuDoivZMcjHXJ9UUS3nMNwU85g
# yDjIGLgDpdzeGb21nrDzj2cG9UrCblgAt8ffL9/efguc3rVvXDMDHdkJmN/XdQpu
# kTunoNgmsdEH/6nAWMb31PAcfq5fMN5lPr+vqofsAAHCfx+lhzVOaV4VjxhG5XPO
# On1WQ8dXxXO/MsvtAraS155csv9jiW+MvqHPI6YT7UtUPeURtiGjXMK34XttT4Wm
# PIF9MLiL/Aeym1vbXxiVuRC3WLUHqWWYnBUXAItfuDFDjxAgZRpwzLySnX7NzNj5
# LGWloSA2ZCR9zWto+H3Lmwxrpfjz7HQrsHw6oOhdxOIQIiMl63HC24GVCx4nTkdF
# +Kx+AWbT2Qbu90cSjc1tS4wwEWKRzhug31R+bSJSGr8m2pXQrCu/0K/drIOB03AR
# aIvZrrkicRZKlFNh+wJDTd6oSHkDevBX8p9QVyK34Os/71VwOmNZGwKiRm/i2Cfm
# oBc0y0drw2KpAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUq5fTYgIUV1eCtwIGYMl8
# fm/8qRcwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEA4LM23h8n6M69C6rQi2ffshmtg0EazACL4gAUzdgYr/AZCUSd
# yCOY0G5pz3lbZ8AvrG0VV8x+R6pIswuqiJ1WxT0GbgMQGNpY05P25f+1xiIlJ8VA
# zSsNuuXxXiczzxFkXnob+olb2Dl0io5KiKbMpS39DtYfpUHJbSxqvnAa+Ci8reoV
# p3ApKHNFhwSpOQcfbOKnl7veN7M8fHb61piokbnEnN0MStnWcyLFGNoezcqlyyZl
# i7GwhF8Fg4m8AUbKZMZG/k+7Cw2mz0RyHUBqyrzgf9j/zE3cZCPg/cyIOfyLNQEM
# K5ch8diTf1uqdoCYVtSIJvL5Zam7N2TigMrP+xbCueyhDva4QZUQ3v6TLD34dKjm
# LyXxmDViaP21SAOlVQaMB26gvIdDteqScqZL2QlIEqTiiQQODQh3ot4otDAfV7hp
# V5PJRjBwFffCDukslBa9HudrZIau2X/bdgZBO52ZY6vKHH2WdTsoEZX9o2/PS1Ol
# yy5ywr5xkUoMSRYH+hQVWu3K6fo0Pmlhk2PQKBG6nmCtUAKr8CBv4Q4YsIP7MS0Y
# 2ini18q+xhvrjbns0n1esweCkKJvvpZPfhE+YIEHLEtSQfEernMLJg27QgVcC3UB
# WJzDXgz5zMtghUzs07JWkV1wHUH0yImKTul5KKLRdNF2Xn9X8qxxNoIEXPcwggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzjCCAjcCAQEwgfih
# gdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAj
# BgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRo
# YWxlcyBUU1MgRVNOOkU1QTYtRTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDRj4LIt7MaBUdYU2Yo
# jUu4T+Fjq6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0G
# CSqGSIb3DQEBBQUAAgUA5vf6eTAiGA8yMDIyMTAxNzIzNTk1M1oYDzIwMjIxMDE4
# MjM1OTUzWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDm9/p5AgEAMAoCAQACAgx4
# AgH/MAcCAQACAhKAMAoCBQDm+Uv5AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
# gYEAUCRkBm2XKhpoTb9W5w0H/e+/viThePgvylahB8ZyoPPdJChFW4FkphHvRFKv
# 7WcPpvKhrw5cpGXsjjYtgq1d7I+Uv+MpIDxo+7uvSInluxY/ivCdkGIAEzwCjs7h
# qYL7OB3IfFWpWlgtqBuYtWkTRmOyQm5lcmZcYqZRIzC6PC0xggQNMIIECQIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZW3/A3W4zcxJQAB
# AAABlTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCBdMrEZ4FwzMLXKI4w8s/TTMU+wxbLS+1vQxaNf
# yE6MHzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIFzmS+GNkAt7aaEjP9B3
# uR5U6YD9wLV3MplPjJssSQLHMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGVt/wN1uM3MSUAAQAAAZUwIgQg3MJv31d3HTE/RkJiHDPc
# gGN33ajYyDjhq3XpnnVhEh8wDQYJKoZIhvcNAQELBQAEggIAMGSfSZvysWeIeP4f
# rIH+MTgOGfSaVx5xNp4WukyTbPvF+rVoMClvxWkMtB0qrbV95Cr9PIJzZkelwYkm
# mdDiO+uaiI6+jxXvLRO7erMzvDHHdu6Lng1Ftr6vt/Il0k2OZLk2AaxlyAiqhO52
# +EkddrihhQ7yDaajkeBbDmadSee8XXmCl6uj5lSCYLjAP5HbAhz5DXLo5wa1MJM1
# 0b40g+4u92l0bdwakxKftViOT5q+Piu5hMLq1ULNqveyca/9le0MEsB1aXOo5V3y
# BHXDX6ceK/LjSp1Jp+cgRfUxs7GTvhvTU3CNFgExEVvQsaaqygfKFQT2VxLW1XIf
# 5b5Es1F+bFWxZUpXfvJJ6y1O0ieK98WeWJGNIFkGRnZRDBZfusEwU+wjXIUbYhPe
# IIfmgPgNKdvRXdmaIXH/d6+1kbD7UDKMVxVHaMSbp94YOCDhekiogLZffYMbd6m8
# 18hU7un3BBJS0H0SkuEScCbp2A6b7cS6x8AxVbTP88K7dYAoeH0JFntdXNAUhcpB
# nMNdyuq+Tt6Bui1WxKmWAIILK9r4EhEC7uyqOU1rH2OiKKZkEAB2uCpHjbYkNIZN
# 86rlyBg9Fn2JX2ZSsDBVvFbDGT3PRI+VKDFKnhOYxuPy80JEeQBxIOQAcaCCUdy/
# HQRlhfo5OPq4Oau0j2kA5oiG/gA=
# SIG # End signature block
