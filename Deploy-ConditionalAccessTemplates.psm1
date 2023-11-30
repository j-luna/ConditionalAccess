## To Do
function Deploy-JLConditionalAccessTemplates {
  param(
    [Parameter(Mandatory=$true)]
    [String]$TemplateJSONPath
  )

  $CAParameters = Get-Content $TemplateJSONPath -Raw | ConvertFrom-Json

  $companyName = $CAParameters.companyName
  $trustedLocations = $CAParameters.trustedLocations
  $allowedCountries = $CAParameters.allowedCountries
  $signInFrequency = $CAParameters.signInFrequency

  if ( ($signInFrequency.unit -eq "days") -and ( ($signInFrequency.value -gt 365) -or ($signInFrequency.value -lt 1) )) {
    Write-Error "Invalid sign-in frequency parameters. If using 'days', value must be between 1 and 365."
    Exit
  }
  if ( ($signInFrequency.unit -eq "hours") -and ( ($signInFrequency.value -gt 23) -or ($signInFrequency.value -lt 1) )) {
    Write-Error "Invalid sign-in frequency parameters. If using 'hours', value must be between 1 and 23."
    Exit
  }


  ## Connect to MS Graph

  $mgGraphScopes = @(
    "Policy.ReadWrite.ConditionalAccess"  # For Conditional Access policy creation
    "Application.Read.All"                # For Conditional Access policy creation
    "Policy.Read.All"                     # For Conditional Access policy creation
    "Group.ReadWrite.All"                 # For security group creation
  ) 

  Connect-MgGraph -Scopes $mgGraphScopes

  Deploy-JLAuthenticationStrength $companyName
  $authenticationStrengthId = Get-MgPolicyAuthenticationStrengthPolicy | Where-Object { $_.DisplayName -eq "$companyName MFA" } | Select-Object -ExpandProperty Id

  Deploy-JLTrustedLocations $trustedLocations

  Deploy-JLNamedCountryLocations $allowedCountries
  $countryNamedLocationsId = Get-MgIdentityConditionalAccessNamedLocation | Where-Object { $_.DisplayName -eq "Allowed Countries" } | Select-Object -ExpandProperty Id

  Deploy-JLTrustedLocationsOnlySecurityGroup
  $trustedLocationsOnlyGroupId = Get-MgGroup | Where-Object { $_.DisplayName -eq "Conditional Access - MFA - Trusted Locations Only" } | Select-Object -ExpandProperty Id

  Deploy-JLGeolocationExclusionsSecurityGroup
  $geolocationExclusionsGroupId = Get-MgGroup | Where-Object { $_.DisplayName -eq "Conditional Access - MFA - Geolocation Exclusions" } | Select-Object -ExpandProperty Id


  ## Create a standard MFA conditional access policy applying to all users.
  ## Source: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-1.0&tabs=powershell

  $standardConditionalAccessParams = @{
    displayName     = "Require multifactor authentication for all users"
    state           = "enabledForReportingButNotEnforced"
    conditions      = @{
      clientAppTypes = @(
        "all"
      )
      applications   = @{
        includeApplications = @(
          "all"
        )
      }
      users          = @{
        includeUsers = @(
          "all"
        )
        excludeRoles = @(
          "d29b2b05-8046-44ba-8758-1e26182fcf32" # Directory Synchronization Accounts
        )
      }
    }
    grantControls   = @{
      operator                               = "OR"
      builtInControls                        = @(
      
      )
      customAuthenticationFactors            = @(
      )
      termsOfUse                             = @(
      )
      "authenticationStrength@odata.context" = "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('845a956d-8ecc-4d76-85d0-15057785bba9')/grantControls/authenticationStrength/$entity"
      authenticationStrength                 = @{
        id = "$authenticationStrengthId"
      }
    }
    sessionControls = @{
      signInFrequency = @{
        authenticationType = "primaryAndSecondaryAuthentication"
        frequencyInterval  = "timeBased"
        isEnabled          = $true
        type               = "days"
        value              = 30
      }
    }
  }
  

  ## Create an admin MFA conditional access policy applying to all privileged accounts.

  $adminConditionalAccessParams = @{
    displayName     = "Require multifactor authentication for all admins"
    state           = "enabledForReportingButNotEnforced"
    conditions      = @{
      clientAppTypes = @(
        "all"
      )
      applications   = @{
        includeApplications = @(
          "all"
        )
      }
      users          = @{
        includeRoles = @(
          "62e90394-69f5-4237-9190-012177145e10",
          "194ae4cb-b126-40b2-bd5b-6091b380977d",
          "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
          "29232cdf-9323-42fd-ade2-1d097af3e4de",
          "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
          "729827e3-9c14-49f7-bb1b-9608f156bbb8",
          "b0f54661-2d74-4c50-afa3-1ec803f12efe",
          "fe930be7-5e62-47db-91af-98c3a49a38b1",
          "c4e39bd9-1100-46d3-8c65-fb160da0071f",
          "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
          "158c047a-c907-4556-b7ef-446551a6b5f7",
          "966707d0-3269-4727-9be2-8c3a10f19b9d",
          "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
          "e8611ab8-c189-46e8-94e1-60213ab1f814"
        )
      }
    }
    grantControls   = @{
      operator                               = "OR"
      builtInControls                        = @(
      )
      customAuthenticationFactors            = @(
      )
      termsOfUse                             = @(
      )
      "authenticationStrength@odata.context" = "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('845a956d-8ecc-4d76-85d0-15057785bba9')/grantControls/authenticationStrength/$entity"
      authenticationStrength                 = @{
        id = "$authenticationStrengthId"
      }
    }
    sessionControls = @{
      signInFrequency = @{
        authenticationType = "primaryAndSecondaryAuthentication"
        frequencyInterval  = "timeBased"
        isEnabled          = $true
        type               = "days"
        value              = 1
      }
    }
  }

  $trustedLocationsOnlyConditionalAccessParams = @{
    displayName   = "Block sign-in for trusted locations security group outside of trusted locations"
    state         = "enabledForReportingButNotEnforced"
    conditions    = @{
      clientAppTypes = @(
        "all"
      )
      applications   = @{
        includeApplications = @(
          "all"
        )
      }
      users          = @{
        includeGroups = @(
          $trustedLocationsOnlyGroupId
        )
      }
      locations      = @{
        includeLocations = @(
          "all"
        )
        excludeLocations = @(
          "alltrusted"
        )
      }
    }
    grantControls = @{
      operator        = "OR"
      builtInControls = @(
        "block"
      )
    }
  }

  $geolocationConditionalAccessParams = @{
    displayName   = "Block sign-in outside of allowed countries"
    state         = "enabledForReportingButNotEnforced"
    conditions    = @{
      clientAppTypes = @(
        "all"
      )
      applications   = @{
        includeApplications = @(
          "all"
        )
      }
      users          = @{
        includeUsers  = @(
          "all"
        )
        excludeGroups = @(
          $geolocationExclusionsGroupId
        )
      }
      locations      = @{
        includeLocations = @(
          "all"
        )
        excludeLocations = @(
          $countryNamedLocationsId
        )
      }
    }
    grantControls = @{
      operator        = "OR"
      builtInControls = @(
        "block"
      )
    }
  }
  
  New-MgIdentityConditionalAccessPolicy -BodyParameter $standardConditionalAccessParams
  New-MgIdentityConditionalAccessPolicy -BodyParameter $adminConditionalAccessParams
  New-MgIdentityConditionalAccessPolicy -BodyParameter $trustedLocationsOnlyConditionalAccessParams
  New-MgIdentityConditionalAccessPolicy -BodyParameter $geolocationConditionalAccessParams

}


## Create custom authentication strength
## Source: https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-post-policies?view=graph-rest-1.0&tabs=powershell
function Deploy-JLAuthenticationStrength {
  param(
    [Parameter(Mandatory=$true)]
    [String]$companyName
  )

  $authenticationStrengthParams = @{
    "@odata.type"       = "#microsoft.graph.authenticationStrengthPolicy"
    displayName         = "$companyName MFA"
    description         = "$companyName custom authentication strength."
    allowedCombinations = @(
      "password, hardwareOath"
      "password, softwareOath"
      "password, microsoftAuthenticatorPush"
      "windowsHelloForBusiness"
      "fido2"
      "x509CertificateMultiFactor"
    )
  }
  
  New-MgPolicyAuthenticationStrengthPolicy -BodyParameter $authenticationStrengthParams
}


## Create trusted named locations for office IP ranges
## Source: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-namedlocations?view=graph-rest-1.0&tabs=powershell

function Deploy-JLTrustedLocations {
  param(
    [Parameter(Mandatory=$true)]
    [Object[]]$trustedLocations
  )

  foreach ($trustedLocation in $trustedLocations) {
    $trustedLocationsParams = @{
      "@odata.type" = "#microsoft.graph.ipNamedLocation"
      displayName   = $trustedLocation.location
      isTrusted     = $true
      ipRanges      = @(
        @{
          "@odata.type" = "#microsoft.graph.iPv4CidrRange"
          cidrAddress   = $trustedLocation.ip
        }
      )
    } 
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $trustedLocationsParams
  }
}

## Create United States named location for geoblocking policy
## Source: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-namedlocations?view=graph-rest-1.0&tabs=powershell

function Deploy-JLNamedCountryLocations {
  param(
    [Parameter(Mandatory=$true)]
    [Object[]]$allowedCountries
  )

  # $allowedCountries = $allowedCountries -join ","

  $countryNamedLocations = @{
    "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
    displayName                       = "Allowed Countries"
    countriesAndRegions               = @($allowedCountries)
    includeUnknownCountriesAndRegions = $false
  }
  
  New-MgIdentityConditionalAccessNamedLocation -BodyParameter $countryNamedLocations

}


## Create the "Conditional Access - MFA - Trusted Locations" security group
## Source: https://learn.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http

function Deploy-JLTrustedLocationsOnlySecurityGroup {
  $trustedLocationsOnlyGroupParams = @{
    description     = "Members of this group can bypass MFA from trusted locations, but are blocked from signing in otherwise."
    displayName     = "Conditional Access - MFA - Trusted Locations Only"
    groupTypes      = @(
    )
    mailNickname = "CA-MFA-TrustedLocationsOnly"
    mailEnabled     = $false
    securityEnabled = $true
  }
  
  New-MgGroup -BodyParameter $trustedLocationsOnlyGroupParams
}

## Create the "Conditional Access - MFA - Geolocation Exclusions" security group
## Source: https://learn.microsoft.com/en-us/graph/api/group-post-groups?view=graph-rest-1.0&tabs=http

function Deploy-JLGeolocationExclusionsSecurityGroup {
  $geolocationExclusionsGroupParams = @{
    description     = "Members of this group are excluded from geolocation conditional access policies."
    displayName     = "Conditional Access - MFA - Geolocation Exclusions"
    groupTypes      = @(
    )
    mailNickname = "CA-MFA-GeolocationExclusions"
    mailEnabled     = $false
    securityEnabled = $true
  }

  New-MgGroup -BodyParameter $geolocationExclusionsGroupParams
}
