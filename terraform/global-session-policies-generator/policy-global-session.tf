data "okta_group" "prod_auth_webauthn_fido2_bypass" {
  name = "auth-webauthn_fido2-bypass"
}

data "okta_group" "prod_app_kolide_users" {
  name = "app_kolide_users"
}

data "okta_group" "prod_service_accounts" {
  name = "Service Accounts"
}

data "okta_group" "prod_idp_citco" {
  name = "idp_citco"
}

data "okta_group" "prod_everyone" {
  name = "Everyone"
}

data "okta_group" "prod_idp_pwc" {
  name = "idp_pwc"
}

data "okta_group" "test_auth_autopilot_test" {
  name = "auth_autopilot_test"
}

data "okta_group" "test_service_accounts" {
  name = "Service Accounts"
}

data "okta_group" "test_auth_webauthn_fido2_bypass" {
  name = "auth-webauthn_fido2-bypass"
}

data "okta_group" "test_everyone" {
  name = "Everyone"
}

data "okta_group" "test_app_kolide_users" {
  name = "app_kolide_users"
}

resource "okta_policy_signon" "policy_prod_00p9rtsvf9f8nb5cx0i7" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "idp_citco"
  status          = "ACTIVE"
  description     = "Applies only to Citco Employees that have initially logged in via an External Identity Provider"
  groups_included = [data.okta_group.prod_idp_citco.id]
  priority        = 1
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00p9rtsvf9f8nb5cx0i7[0]
  id       = "00p9rtsvf9f8nb5cx0i7"
}

resource "okta_policy_signon" "policy_prod_00p9rtve25V3GLbpf0i7" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "idp_pwc"
  status          = "ACTIVE"
  description     = "Sets Session Policies for PWC employees that log in via their external Identity Provider."
  groups_included = [data.okta_group.prod_idp_pwc.id]
  priority        = 2
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00p9rtve25V3GLbpf0i7[0]
  id       = "00p9rtve25V3GLbpf0i7"
}

resource "okta_policy_signon" "policy_prod_00p9pl7138mm8fLfm0i7" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "Service Accounts"
  status          = "ACTIVE"
  description     = "Sets a Login Session Policy for Service Accounts"
  groups_included = [data.okta_group.prod_service_accounts.id]
  priority        = 3
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0]
  id       = "00p9pl7138mm8fLfm0i7"
}

resource "okta_policy_signon" "policy_prod_00pci1e3xc6gvitgg0i7" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "Kolide - GSP"
  status          = "INACTIVE"
  description     = "Used for Kolide GSP Session"
  groups_included = [data.okta_group.prod_app_kolide_users.id]
  priority        = 4
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00pci1e3xc6gvitgg0i7[0]
  id       = "00pci1e3xc6gvitgg0i7"
}

resource "okta_policy_signon" "policy_prod_00pa8ex1884jnhChp0i7" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "Bypass Okta FastPass / Device Trust"
  status          = "ACTIVE"
  description     = "FIDO Bypass, Allows for the use of a OTP Token or FIDO Key to bypass an employee's Device Trust Setup. Should not be used for"
  groups_included = [data.okta_group.prod_auth_webauthn_fido2_bypass.id]
  priority        = 5
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00pa8ex1884jnhChp0i7[0]
  id       = "00pa8ex1884jnhChp0i7"
}

resource "okta_policy_signon" "policy_prod_00p9vpy33k5FETEPZ0i7" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "EQT Default User Policy"
  status          = "ACTIVE"
  description     = "Global Session Policy Created after OIE Upgrade, to be used with Device Trust based policies."
  groups_included = [data.okta_group.prod_everyone.id]
  priority        = 6
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00p9vpy33k5FETEPZ0i7[0]
  id       = "00p9vpy33k5FETEPZ0i7"
}

resource "okta_policy_signon" "policy_prod_00p2devtiLfky64cS0i6" {
  count           = var.CONFIG == "prod" ? 1 : 0
  name            = "Default Policy"
  status          = "ACTIVE"
  description     = "The default policy applies in all situations if no other policy applies."
  groups_included = [data.okta_group.prod_everyone.id]
  priority        = 7
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_signon.policy_prod_00p2devtiLfky64cS0i6[0]
  id       = "00p2devtiLfky64cS0i6"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9rtuewx84ZbqxP0i7" {
  count                 = var.CONFIG == "prod" ? 1 : 0
  name                  = "Citco External IDP Global Session Rule"
  status                = "ACTIVE"
  access                = "ALLOW"
  authtype              = "ANY"
  behaviors             = []
  network_connection    = "ANYWHERE"
  identity_provider     = "SPECIFIC_IDP"
  identity_provider_ids = ["0oae1yk615RGSUJAk0i7"]
  mfa_lifetime          = 0
  mfa_remember_device   = false
  mfa_required          = false
  primary_factor        = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded        = []
  priority              = 1
  risc_level            = "ANY"
  risk_level            = "ANY"
  session_idle          = 720
  session_lifetime      = 1440
  session_persistent    = false
  policy_id             = okta_policy_signon.policy_prod_00p9rtsvf9f8nb5cx0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9rtuewx84ZbqxP0i7[0]
  id       = "00p9rtsvf9f8nb5cx0i7/0pr9rtuewx84ZbqxP0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9rtuqa583521Ly0i7" {
  count                 = var.CONFIG == "prod" ? 1 : 0
  name                  = "PWC External IDP Global Session Rule"
  status                = "ACTIVE"
  access                = "ALLOW"
  authtype              = "ANY"
  behaviors             = []
  network_connection    = "ANYWHERE"
  identity_provider     = "SPECIFIC_IDP"
  identity_provider_ids = ["0oa6e59jf8vUEtMsw0i7", "0oa6f4aokihHXP4kb0i7"]
  mfa_lifetime          = 0
  mfa_remember_device   = false
  mfa_required          = false
  primary_factor        = "PASSWORD_IDP"
  users_excluded        = []
  priority              = 1
  risc_level            = "ANY"
  risk_level            = "ANY"
  session_idle          = 720
  session_lifetime      = 1440
  session_persistent    = false
  policy_id             = okta_policy_signon.policy_prod_00p9rtve25V3GLbpf0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9rtuqa583521Ly0i7[0]
  id       = "00p9rtve25V3GLbpf0i7/0pr9rtuqa583521Ly0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pra1fn2e5IdSbU2Y0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Password Only LDAP"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "LDAP_INTERFACE"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 0
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pra1fn2e5IdSbU2Y0i7[0]
  id       = "00p9pl7138mm8fLfm0i7/0pra1fn2e5IdSbU2Y0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9zcc9feYPmelee0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "High Risk, Require MFA on LDAP Interface"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "LDAP_INTERFACE"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "ALWAYS"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = ["00u4y7tiz51oiBpLt0i7"]
  priority            = 2
  risc_level          = "HIGH"
  risk_level          = "HIGH"
  session_idle        = 720
  session_lifetime    = 1440
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9zcc9feYPmelee0i7[0]
  id       = "00p9pl7138mm8fLfm0i7/0pr9zcc9feYPmelee0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9zccdumpfFJuei0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Do not require MFA on LDAP Interface"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "LDAP_INTERFACE"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 3
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 1440
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9zccdumpfFJuei0i7[0]
  id       = "00p9pl7138mm8fLfm0i7/0pr9zccdumpfFJuei0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9pl7susCGAXNYY0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Service Account High Risk Login, Require MFA"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "ALWAYS"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 4
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 1440
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9pl7susCGAXNYY0i7[0]
  id       = "00p9pl7138mm8fLfm0i7/0pr9pl7susCGAXNYY0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9pl7hhu20mR9Ml0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Service Account, Default Rule"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 5
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 1440
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9pl7hhu20mR9Ml0i7[0]
  id       = "00p9pl7138mm8fLfm0i7/0pr9pl7hhu20mR9Ml0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pra1dpng68r1n3XN0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Password Only"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 6
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 0
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9pl7138mm8fLfm0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pra1dpng68r1n3XN0i7[0]
  id       = "00p9pl7138mm8fLfm0i7/0pra1dpng68r1n3XN0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0prci1dot2u5ZqCTs0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Kolide Device Trust"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 480
  session_lifetime    = 720
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00pci1e3xc6gvitgg0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0prci1dot2u5ZqCTs0i7[0]
  id       = "00pci1e3xc6gvitgg0i7/0prci1dot2u5ZqCTs0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pra8ezcu6QWB8jpK0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Fido Only"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 60
  session_lifetime    = 120
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00pa8ex1884jnhChp0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pra8ezcu6QWB8jpK0i7[0]
  id       = "00pa8ex1884jnhChp0i7/0pra8ezcu6QWB8jpK0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9vpxweqWF71dGm0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "High Risk, Require MFA"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 1
  risc_level          = "HIGH"
  risk_level          = "HIGH"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9vpy33k5FETEPZ0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9vpxweqWF71dGm0i7[0]
  id       = "00p9vpy33k5FETEPZ0i7/0pr9vpxweqWF71dGm0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr9zldoco7J8nsvy0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Behavior Evaluation, Require MFA"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = [okta_behavior.new_country.id, okta_behavior.new_state.id, okta_behavior.velocity.id, okta_behavior.new_geo_location.id]
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 2
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9vpy33k5FETEPZ0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr9zldoco7J8nsvy0i7[0]
  id       = "00p9vpy33k5FETEPZ0i7/0pr9zldoco7J8nsvy0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0prc6w98ckzXvrys50i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Default Rule - Passwordless"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 3
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p9vpy33k5FETEPZ0i7[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0prc6w98ckzXvrys50i7[0]
  id       = "00p9vpy33k5FETEPZ0i7/0prc6w98ckzXvrys50i7"
}

resource "okta_policy_rule_signon" "rule_prod_0prabgftgaOcZ9nJE0i7" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Deny Rule in Default Policy"
  status              = "ACTIVE"
  access              = "DENY"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 120
  session_lifetime    = 0
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p2devtiLfky64cS0i6[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0prabgftgaOcZ9nJE0i7[0]
  id       = "00p2devtiLfky64cS0i6/0prabgftgaOcZ9nJE0i7"
}

resource "okta_policy_rule_signon" "rule_prod_0pr2devtjKhC78X7X0i6" {
  count               = var.CONFIG == "prod" ? 1 : 0
  name                = "Default Rule"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 2
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 600
  session_lifetime    = 0
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_prod_00p2devtiLfky64cS0i6[0].id
}

import {
  for_each = var.CONFIG == "prod" ? toset(["prod"]) : []
  to       = okta_policy_rule_signon.rule_prod_0pr2devtjKhC78X7X0i6[0]
  id       = "00p2devtiLfky64cS0i6/0pr2devtjKhC78X7X0i6"
}

resource "okta_policy_signon" "policy_test_00p1z2cyh8aOtKeKh0h8" {
  count           = var.CONFIG == "test" ? 1 : 0
  name            = "Kolide - Test"
  status          = "ACTIVE"
  description     = "asdf"
  groups_included = [data.okta_group.test_app_kolide_users.id]
  priority        = 1
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_signon.policy_test_00p1z2cyh8aOtKeKh0h8[0]
  id       = "00p1z2cyh8aOtKeKh0h8"
}

resource "okta_policy_signon" "policy_test_00p1isq5hbmhglwcW0h8" {
  count           = var.CONFIG == "test" ? 1 : 0
  name            = "Service Accounts"
  status          = "ACTIVE"
  description     = "Sets a login session policy for Service Accounts."
  groups_included = [data.okta_group.test_service_accounts.id]
  priority        = 2
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_signon.policy_test_00p1isq5hbmhglwcW0h8[0]
  id       = "00p1isq5hbmhglwcW0h8"
}

resource "okta_policy_signon" "policy_test_00p1npcqevgCfxoht0h8" {
  count           = var.CONFIG == "test" ? 1 : 0
  name            = "Autopilot Policy Test"
  status          = "INACTIVE"
  description     = "Test"
  groups_included = [data.okta_group.test_auth_autopilot_test.id, data.okta_group.test_auth_webauthn_fido2_bypass.id]
  priority        = 3
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_signon.policy_test_00p1npcqevgCfxoht0h8[0]
  id       = "00p1npcqevgCfxoht0h8"
}

resource "okta_policy_signon" "policy_test_00p2bauyxczdkCUwx0h8" {
  count           = var.CONFIG == "test" ? 1 : 0
  name            = "Github / TF Flow Changes"
  status          = "ACTIVE"
  description     = "Backup"
  groups_included = [data.okta_group.test_everyone.id]
  priority        = 4
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_signon.policy_test_00p2bauyxczdkCUwx0h8[0]
  id       = "00p2bauyxczdkCUwx0h8"
}

resource "okta_policy_signon" "policy_test_00p60ljl0xNYlTXhW0h7" {
  count           = var.CONFIG == "test" ? 1 : 0
  name            = "Default Policy"
  status          = "ACTIVE"
  description     = "The default policy applies in all situations if no other policy applies."
  groups_included = [data.okta_group.test_everyone.id]
  priority        = 5
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_signon.policy_test_00p60ljl0xNYlTXhW0h7[0]
  id       = "00p60ljl0xNYlTXhW0h7"
}

resource "okta_policy_rule_signon" "rule_test_0pr1z2d0k3fXVlrot0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Default Rule - Device Trust"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 0
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p1z2cyh8aOtKeKh0h8[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr1z2d0k3fXVlrot0h8[0]
  id       = "00p1z2cyh8aOtKeKh0h8/0pr1z2d0k3fXVlrot0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr1isqauqiF8hPzo0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Default Sign On"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 1440
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p1isq5hbmhglwcW0h8[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr1isqauqiF8hPzo0h8[0]
  id       = "00p1isq5hbmhglwcW0h8/0pr1isqauqiF8hPzo0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr1npcu5x8aQgjQp0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Default"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 720
  session_lifetime    = 43200
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p1npcqevgCfxoht0h8[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr1npcu5x8aQgjQp0h8[0]
  id       = "00p1npcqevgCfxoht0h8/0pr1npcu5x8aQgjQp0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr2bausb9uZV4T0p0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Default Rule"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p2bauyxczdkCUwx0h8[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr2bausb9uZV4T0p0h8[0]
  id       = "00p2bauyxczdkCUwx0h8/0pr2bausb9uZV4T0p0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr1isqy4hfRVirpJ0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "EQT Default Policy"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 1
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p60ljl0xNYlTXhW0h7[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr1isqy4hfRVirpJ0h8[0]
  id       = "00p60ljl0xNYlTXhW0h7/0pr1isqy4hfRVirpJ0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr1isqfw80z4BXbn0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Behavior Detection - Require MFA"
  status              = "INACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = [okta_behavior.new_country.id, okta_behavior.new_state.id, okta_behavior.new_ip.id, okta_behavior.velocity.id, okta_behavior.new_geo_location.id]
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 2
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p60ljl0xNYlTXhW0h7[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr1isqfw80z4BXbn0h8[0]
  id       = "00p60ljl0xNYlTXhW0h7/0pr1isqfw80z4BXbn0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr1h4bpojtn746zy0h8" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Behavior Detection - New Device"
  status              = "INACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_prompt          = "DEVICE"
  mfa_remember_device = false
  mfa_required        = true
  primary_factor      = "PASSWORD_IDP_ANY_FACTOR"
  users_excluded      = []
  priority            = 3
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 1440
  session_lifetime    = 10080
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p60ljl0xNYlTXhW0h7[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr1h4bpojtn746zy0h8[0]
  id       = "00p60ljl0xNYlTXhW0h7/0pr1h4bpojtn746zy0h8"
}

resource "okta_policy_rule_signon" "rule_test_0pr60ljl0ygAwpaGV0h7" {
  count               = var.CONFIG == "test" ? 1 : 0
  name                = "Default Rule"
  status              = "ACTIVE"
  access              = "ALLOW"
  authtype            = "ANY"
  behaviors           = []
  network_connection  = "ANYWHERE"
  identity_provider   = "ANY"
  mfa_lifetime        = 0
  mfa_remember_device = false
  mfa_required        = false
  primary_factor      = "PASSWORD_IDP"
  users_excluded      = []
  priority            = 4
  risc_level          = "ANY"
  risk_level          = "ANY"
  session_idle        = 120
  session_lifetime    = 0
  session_persistent  = false
  policy_id           = okta_policy_signon.policy_test_00p60ljl0xNYlTXhW0h7[0].id
}

import {
  for_each = var.CONFIG == "test" ? toset(["test"]) : []
  to       = okta_policy_rule_signon.rule_test_0pr60ljl0ygAwpaGV0h7[0]
  id       = "00p60ljl0xNYlTXhW0h7/0pr60ljl0ygAwpaGV0h7"
}

