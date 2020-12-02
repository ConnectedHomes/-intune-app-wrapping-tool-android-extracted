#  ----------------------------------------------------------------------
#   Copyright (c) Microsoft Corporation.  All rights reserved.
#  ----------------------------------------------------------------------

function Invoke-AppWrappingTool
{
  <#
  .SYNOPSIS
  Package an internal LOB application to support Application Policy Restrictions.
  .DESCRIPTION
  Microsoft Intune App Wrapping Tool for Android
  Copyright Microsoft

  The Microsoft Intune App Wrapping Tool for Android provides the ability to extend mobile application management (MAM) to existing line-of-business apps.
  The tool is a Windows PowerShell application that creates a ‘wrapper’ around an app.
  In order for an application to be wrapped, it must be signed and encrypted.
  Specify -Verbose to see detailed messages at every step of the application wrapping.
  .EXAMPLE
  Invoke-AppWrappingTool  -InputPath C:\apps\androidApplication.apk  -OutputPath C:\packagedApplication.apk
  Output: a wrapped Android application that will support mobile application management.
  Wraps an Android application with the Intune App Wrapping Tool so that it supports mobile application management.
  .EXAMPLE
  Invoke-AppWrappingTool  -InputPath C:\apps\androidApplication.apk  -OutputPath C:\packagedApplication.apk  -ClientID 309a37cd-4246-4a78-b5b2-ee453cecd9ee
  Output: a wrapped Android application that will support mobile application management.
  Wraps an Android application that uses the Azure Active Directory library with the Intune App Wrapping Tool so that it supports mobile application management.
  .PARAMETER InputPath
   Path to the input Android application.
  .PARAMETER OutputPath
   Path to the output Android application. If this is the same directory path as InputPath, the packaging will fail.
  .PARAMETER KeyStorePath
   Path to the keystore file containing the public/private key pair for signing.
  .PARAMETER KeyStorePassword
   Password to decrypt the keystore.
  .PARAMETER KeyAlias
   Name of the key to be used for signing.
  .PARAMETER KeyPassword
   Password to decrypt the private key to be used for signing.
  .PARAMETER SigAlg
   Name of signature algorithm to be used for signing. The algorithm must be compatible with the private key. Examples: SHA256withRSA, SHA1withRSA, MD5withRSA
  .PARAMETER UseMinAPILevelForNativeMultiDex
   Sets the wrapped application's minimum API level to 21. Restricts support to native MultiDex devices. Enables dex file balancing for dex overflow prevention. Warning: increasing the minimum API level may prevent some users from installing the wrapped application.
  #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact = "High", DefaultParameterSetName='Base')]
    param(
        [Parameter(ParameterSetName='Base', Mandatory=$true, Position=0)]
        [Parameter(ParameterSetName='Signing', Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        ${InputPath},

        [Parameter(ParameterSetName='Base', Mandatory=$true, Position=1)]
        [Parameter(ParameterSetName='Signing', Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        ${OutputPath},

        [Parameter(ParameterSetName='Signing',Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        ${KeyStorePath},

        [Parameter(ParameterSetName='Signing',Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        ${KeyStorePassword},

        [Parameter(ParameterSetName='Signing',Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        ${KeyAlias},

        [Parameter(ParameterSetName='Signing',Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]
        ${KeyPassword},

        [Parameter(ParameterSetName='Signing')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        ${SigAlg},

        [Switch]
        ${UseMinAPILevelForNativeMultiDex}
    )

    begin
    {
        $exe = "java.exe";
        $jar = "$PSScriptRoot\lib\IntuneAppWrappingTool.jar";

        if (!(test-path $jar))
        {
            throw("Cannot find IntuneAppWrappingTool.jar. Please ensure " +
                  "IntuneAppWrappingTool.jar is in the same directory as the cmdlet script.");
            Break
        }

        if ((test-path $OutputPath))
        {
            throw("The application $OutputPath already exists. Please specify a new application location.");
            Break
        }

        #Using a path relative to $PSScriptRoot makes the module runnable no matter the current working directory.
        #Quotes around path parameters are not preserved when put into a string. Manually wrap each parameter in
        #quotes to ensure proper parameter grouping.
        $cmdline = '-jar $jar -i "$InputPath" -o "$OutputPath"';

        if ($PSBoundParameters['Verbose'])
        {
            $cmdline += ' --verbose';
        }

        if ($KeyStorePath)
        {
            $cmdline += ' --keystorepath "$KeyStorePath"';
        }

        if ($KeyStorePassword)
        {
            $storePW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyStorePassword));
            $cmdline += ' --keystorepassword "$storePW"';
        }

        if ($KeyAlias)
        {
            $cmdline += ' --keyalias "$KeyAlias"';
        }

        if ($KeyPassword)
        {
            $keyPW = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyPassword));
            $cmdline += ' --keypassword "$keyPW"';
        }

        if ($SigAlg)
        {
            $cmdline += ' --sigalg "$SigAlg"';
        }

        if ($UseMinAPILevelForNativeMultiDex)
        {
            Confirm-UseMinAPILevelForNativeMultiDex;
            $cmdline += ' --minsdk 21';
        }
    }

    process
    {
        if ($WhatIfPreference)
        {
            # Don't actually perform the wrapping.
            return;
        }

        try
        {
            return Invoke-Expression -Command "$exe $cmdline"
        }
        catch [System.Management.Automation.CommandNotFoundException]
        {

            throw("Cannot find $exe. Please ensure $exe is installed and on your %PATH%.");
        }
    }

    end
    {

    }

}

function Confirm-UseMinAPILevelForNativeMultiDex
{
    # Prompt the user to confirm the min API level bump.
    $ShouldProcess = $PSCmdlet.ShouldProcess(
            [ProductionMessages]::MIN_API_LEVEL_FOR_NATIVE_MULTIDEX_DESC,
            [ProductionMessages]::MIN_API_LEVEL_FOR_NATIVE_MULTIDEX_WARN,
            [ProductionMessages]::MIN_API_LEVEL_FOR_NATIVE_MULTIDEX_CAPTION)

    if ($ShouldProcess -or $WhatIfPreference)
    {
        return;
    }

    throw([ProductionMessages]::WRAPPING_HALTED_BY_USER);
}

function Validate-Uri($Uri)
{
    if (($Uri -as [System.URI]).isAbsoluteUri)
    {
        $True
    }
    else
    {
        throw("$Uri is not a valid URI.");
    }
}

class ProductionMessages {
    # Description for the confirmation triggered by the UseMinAPILevelForNativeMultidex switch.
    static [System.String] $MIN_API_LEVEL_FOR_NATIVE_MULTIDEX_DESC = "Use the minimum API level for native MultiDex support.";
    # Warning message for the confirmation triggered by the UseMinAPILevelForNativeMultidex switch.
    static [System.String] $MIN_API_LEVEL_FOR_NATIVE_MULTIDEX_WARN = "Setting the the wrapped application's minimum API level to 21. This may prevent some users from installing the application. Do you want to proceed?";
    # Caption for the confirmation triggered by the UseMinAPILevelForNativeMultidex switch.
    static [System.String] $MIN_API_LEVEL_FOR_NATIVE_MULTIDEX_CAPTION = "Use Minimum API level for Native MultiDex";
    # Message to display when the wrapping is halted by user input.
    static [System.String] $WRAPPING_HALTED_BY_USER = "App wrapping halted by the user.";
}

Export-ModuleMember Invoke-AppWrappingTool

# SIG # Begin signature block
# MIIjhgYJKoZIhvcNAQcCoIIjdzCCI3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDb6FTW5YDC1nPJ
# inIh3WAoFwwCF07I6JHpkqrhYgpXCaCCDYEwggX/MIID56ADAgECAhMzAAABh3IX
# chVZQMcJAAAAAAGHMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAwMzA0MTgzOTQ3WhcNMjEwMzAzMTgzOTQ3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDOt8kLc7P3T7MKIhouYHewMFmnq8Ayu7FOhZCQabVwBp2VS4WyB2Qe4TQBT8aB
# znANDEPjHKNdPT8Xz5cNali6XHefS8i/WXtF0vSsP8NEv6mBHuA2p1fw2wB/F0dH
# sJ3GfZ5c0sPJjklsiYqPw59xJ54kM91IOgiO2OUzjNAljPibjCWfH7UzQ1TPHc4d
# weils8GEIrbBRb7IWwiObL12jWT4Yh71NQgvJ9Fn6+UhD9x2uk3dLj84vwt1NuFQ
# itKJxIV0fVsRNR3abQVOLqpDugbr0SzNL6o8xzOHL5OXiGGwg6ekiXA1/2XXY7yV
# Fc39tledDtZjSjNbex1zzwSXAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUhov4ZyO96axkJdMjpzu2zVXOJcsw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU4Mzg1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAixmy
# S6E6vprWD9KFNIB9G5zyMuIjZAOuUJ1EK/Vlg6Fb3ZHXjjUwATKIcXbFuFC6Wr4K
# NrU4DY/sBVqmab5AC/je3bpUpjtxpEyqUqtPc30wEg/rO9vmKmqKoLPT37svc2NV
# BmGNl+85qO4fV/w7Cx7J0Bbqk19KcRNdjt6eKoTnTPHBHlVHQIHZpMxacbFOAkJr
# qAVkYZdz7ikNXTxV+GRb36tC4ByMNxE2DF7vFdvaiZP0CVZ5ByJ2gAhXMdK9+usx
# zVk913qKde1OAuWdv+rndqkAIm8fUlRnr4saSCg7cIbUwCCf116wUJ7EuJDg0vHe
# yhnCeHnBbyH3RZkHEi2ofmfgnFISJZDdMAeVZGVOh20Jp50XBzqokpPzeZ6zc1/g
# yILNyiVgE+RPkjnUQshd1f1PMgn3tns2Cz7bJiVUaqEO3n9qRFgy5JuLae6UweGf
# AeOo3dgLZxikKzYs3hDMaEtJq8IP71cX7QXe6lnMmXU/Hdfz2p897Zd+kU+vZvKI
# 3cwLfuVQgK2RZ2z+Kc3K3dRPz2rXycK5XCuRZmvGab/WbrZiC7wJQapgBodltMI5
# GMdFrBg9IeF7/rP4EqVQXeKtevTlZXjpuNhhjuR+2DMt/dWufjXpiW91bo3aH6Ea
# jOALXmoxgltCp1K7hrS6gmsvj94cLRf50QQ4U8Qwggd6MIIFYqADAgECAgphDpDS
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWzCCFVcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAYdyF3IVWUDHCQAAAAABhzAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgTc6xOgQg
# c0qcOFXy/22BgW1ZNgxhVMdJl7m3YnjPi9swQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAiRmH8HKR+iwrueSc9j2r08WVwo0jsM2+M0eGIq8ZX
# eKfNvWUiIxsW76NJDMvu8injY3+JR6W2rmpITLlvqLuzXHZch94qMD9xRopLYfrE
# /tqYWzAZm/XVGuF8ayp9+MNmZFS1NRTYxFcHIOeHYm2phJ+UH1yo9xcebZLJ3tjd
# vjq53MDs26ikvSQap5DDfAhgZjqcVeksFZiaaPeOlHGz3Xar/NBybIu2+bdZ3Yz/
# fqgqZBWh57r3e0ba6MjUfx8l1WfeqUP8+URS5ysdY0eEezpt8mpgJu12in9xnSIP
# gluPyw11uiY70L0eVO6BJkPNEoHf6rmXAQS8HXUDQ/DQoYIS5TCCEuEGCisGAQQB
# gjcDAwExghLRMIISzQYJKoZIhvcNAQcCoIISvjCCEroCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIDYAcBlyjJugW1IN1FzVGSsKg48sIpdJA7pBfLKw
# 3u5jAgZezodXzTsYEzIwMjAwNjA1MTQwOTM3LjI3NFowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOPDCCBPEwggPZoAMCAQICEzMAAAEWkyLqv7stTeYAAAAAARYw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTkxMTEzMjE0MDM0WhcNMjEwMjExMjE0MDM0WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QUUyQy1FMzJCLTFB
# RkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQ+Bvz/b3qJ78uPatar4wiUxnCRJTB
# mwgp3jva3J5U7I1wqCpIJPjNC/PaR35UPuVhY3dXRRIvmiKl2n7GnvAfsIAcLvM1
# TbU+N0dY86LaiQiU/JOKStAGjCj4w5X1eB3daoyclIoRqeTtCZIeAmKYnar9lFHn
# 7Rnm5lF6MkeRBwmZMHwar/CDYT+CO5GX+IZrh8Ym7RwdJSJfvybkUTJppzVeeSpp
# 9KphHypvuyfdlW3+W1uIZQmvzviiLZtl25S0IxHRCJZZ8EwTFwtXgDp6uYL3xxtu
# +L+lBvWnWXu9dPY1F4P7GQWrMqfRwDdWL1xzkuMOFj3UvXxG4ciBTeodAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQU5b9eK7gX6BfNR+UfeTT+V8ghVQswHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEANoNq19qpo9sDL+lJ0rx7xd3M3q/33v01JYtSw0eg
# 0EWnKvUVMZy/B/RIoh97TKC3yzymWQBjExR+1SY6c746cZdSBM6t5cjDjO2x6mi2
# t4dwvT3j5ufs5QYs8xrnoZCKLdZSCIY8/SB81eFdypJ130eZeMyEp9GfSM4pEQlM
# +o8ctdLFwDVJVOuDwkO2QP7JZXO64CRKilMbG0mnk9ythSsxvudbVygh7u2xCJI+
# nrEVXMp9cVQn1XMAKG5wT7ympculX/FTen/W9/QOAtkykjbabACBt78TrCDINIrI
# dcjhSyIiVJgBK/4iUo61xfOtdXQhFBR1HIgLVmJZYv9iCDCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs4wggI3AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUzMkItMUFG
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAh01b3PJPoIsbWoIM1z76zOzdlkOggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOKEOogwIhgPMjAy
# MDA2MDUxMTI5MTJaGA8yMDIwMDYwNjExMjkxMlowdzA9BgorBgEEAYRZCgQBMS8w
# LTAKAgUA4oQ6iAIBADAKAgEAAgIXWQIB/zAHAgEAAgISQTAKAgUA4oWMCAIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAFRdwkRi/v4JCZMWjGoklX3pLOgtuX/f
# XrPJRYUS3KWO//3pV1wJXrojfQa6FoqfrhTJCwOfZ5Eu8c1cXce5giQeL3DMWR2h
# YvjDqKd1tOsAfBbMGJHYb9ZqUbhFAtrLbvxF+kjz5se/9Dc5aazjgzYu6napEYZJ
# J/s6j6dIhYpeMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAEWkyLqv7stTeYAAAAAARYwDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgR5+6vL0M
# LUmDRzw7hD9TlkBXKWT4RMBqU72oTdl+8JMwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCCDIpT2pGApCJdcKZshNt20sQ2FjGogyEFoz6Je0sGQyjCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABFpMi6r+7LU3mAAAA
# AAEWMCIEIPGF+jZ1cm13Id/UM5+gwTaogIVQoQxhhOtXr6O5q4pMMA0GCSqGSIb3
# DQEBCwUABIIBAHL1Qo3KykU9n5rQ8rlZS2KW1LNHOCSzvrm/VcNLmSG8fk+MKG4B
# 9WG0+J3k8ZZbNYqrPEngfh4w52i7EV4yDIuJMmo/xX3vvoGooZ14sgd9tkf0sraH
# xoADQsg/narGfoFm8T5YfGddoLvkUF4YwHn4Mf78qQXDPbWqJDau2kYhToZ6S/BX
# W3eGe/T3FYP+FcPNwyfJrrXku/b6dQGu2tx2Yh5ZZHQJbTvaVfJTITFQZNZypd4H
# +SIZ238OCiEA8gU2+TASasBgoQeQct/wt4fPiG16QebTA3ExEaotO531btl9Gz5X
# s2F1wjCpGndTYiWn6tvUGZPNgvEt71Cp8AI=
# SIG # End signature block
