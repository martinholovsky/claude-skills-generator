# Kanidm Integration Guide

This guide provides comprehensive integration examples for Kanidm with various systems and protocols.

---

## Table of Contents

1. [LDAP Integration](#ldap-integration)
2. [OAuth2/OIDC Integration](#oauth2oidc-integration)
3. [RADIUS Integration](#radius-integration)
4. [PAM Integration](#pam-integration)
5. [SSH Key Management](#ssh-key-management)
6. [Kubernetes Integration](#kubernetes-integration)
7. [Application Examples](#application-examples)

---

## LDAP Integration

### Basic LDAP Setup

```bash
# Create dedicated LDAP service account
kanidm service-account create ldap_bind "LDAP Bind Account for Legacy Systems"

# Set a strong password
kanidm service-account credential set-password ldap_bind
# Enter strong password when prompted

# Grant minimal LDAP read privileges
kanidm group add-members idm_account_read_priv ldap_bind

# Test LDAP connectivity
ldapsearch -H ldaps://idm.example.com:3636 \
  -D "name=ldap_bind,dc=idm,dc=example,dc=com" \
  -W \
  -b "dc=idm,dc=example,dc=com" \
  "(objectClass=*)" \
  -LLL
```

### LDAP Integration with Grafana

```yaml
# grafana.ini
[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml
allow_sign_up = true

# /etc/grafana/ldap.toml
[[servers]]
host = "idm.example.com"
port = 3636
use_ssl = true
start_tls = false
ssl_skip_verify = false

bind_dn = "name=ldap_bind,dc=idm,dc=example,dc=com"
bind_password = 'your-ldap-bind-password'

search_filter = "(uid=%s)"
search_base_dns = ["dc=idm,dc=example,dc=com"]

# Map LDAP groups to Grafana roles
[[servers.group_mappings]]
group_dn = "cn=grafana_admins,dc=idm,dc=example,dc=com"
org_role = "Admin"

[[servers.group_mappings]]
group_dn = "cn=grafana_editors,dc=idm,dc=example,dc=com"
org_role = "Editor"

[[servers.group_mappings]]
group_dn = "cn=grafana_viewers,dc=idm,dc=example,dc=com"
org_role = "Viewer"

# Attribute mapping
[servers.attributes]
name = "displayName"
surname = "sn"
username = "uid"
member_of = "memberOf"
email = "mail"
```

```bash
# Create Grafana groups in Kanidm
kanidm group create grafana_admins "Grafana Administrators"
kanidm group create grafana_editors "Grafana Editors"
kanidm group create grafana_viewers "Grafana Viewers"

# Add users to groups
kanidm group add-members grafana_admins alice
kanidm group add-members grafana_editors bob
kanidm group add-members grafana_viewers charlie
```

### LDAP Integration with NextCloud

```php
// config/config.php
'ldapIgnoreNamingRules' => false,
'ldapProviderFactory' => \OC\User\LDAPProviderFactory::class,

// Manual LDAP configuration
$CONFIG = array(
  'ldap' => array(
    's01' => array(
      'ldap_host' => 'ldaps://idm.example.com:3636',
      'ldap_port' => '3636',
      'ldap_base' => 'dc=idm,dc=example,dc=com',
      'ldap_base_users' => 'dc=idm,dc=example,dc=com',
      'ldap_base_groups' => 'dc=idm,dc=example,dc=com',
      'ldap_dn' => 'name=ldap_bind,dc=idm,dc=example,dc=com',
      'ldap_agent_password' => 'your-ldap-bind-password',
      'ldap_login_filter' => '(&(objectClass=person)(uid=%uid))',
      'ldap_userlist_filter' => '(objectClass=person)',
      'ldap_group_filter' => '(objectClass=groupOfNames)',
      'ldap_display_name' => 'displayName',
      'ldap_email_attr' => 'mail',
      'ldap_group_member_assoc_attribute' => 'member',
      'ldap_tls_verify_certificate' => true,
    ),
  ),
);
```

### LDAP Troubleshooting

```bash
# Debug LDAP search
ldapsearch -H ldaps://idm.example.com:3636 \
  -D "name=ldap_bind,dc=idm,dc=example,dc=com" \
  -W \
  -b "dc=idm,dc=example,dc=com" \
  -d 1 \
  "(uid=testuser)"

# Check user attributes
ldapsearch -H ldaps://idm.example.com:3636 \
  -D "name=ldap_bind,dc=idm,dc=example,dc=com" \
  -W \
  -b "dc=idm,dc=example,dc=com" \
  "(uid=jsmith)" \
  uid displayName mail memberOf uidNumber gidNumber

# Verify group membership
ldapsearch -H ldaps://idm.example.com:3636 \
  -D "name=ldap_bind,dc=idm,dc=example,dc=com" \
  -W \
  -b "dc=idm,dc=example,dc=com" \
  "(&(objectClass=groupOfNames)(member=uid=jsmith,dc=idm,dc=example,dc=com))"

# Test TLS certificate
openssl s_client -connect idm.example.com:3636 -showcerts
```

---

## OAuth2/OIDC Integration

### GitLab OAuth2/OIDC

```bash
# Register OAuth2 client in Kanidm
kanidm oauth2 create gitlab_oidc "GitLab SSO" \
  --origin https://gitlab.example.com

# Add redirect URI
kanidm oauth2 add-redirect-url gitlab_oidc \
  https://gitlab.example.com/users/auth/openid_connect/callback

# Enable scopes
kanidm oauth2 enable-scope gitlab_oidc openid email profile groups

# Set token lifetimes (1 hour access, 24 hour refresh)
kanidm oauth2 set-token-lifetime gitlab_oidc --access 3600 --refresh 86400

# Get client credentials
kanidm oauth2 show-basic-secret gitlab_oidc
```

```ruby
# GitLab config/gitlab.rb
gitlab_rails['omniauth_enabled'] = true
gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']
gitlab_rails['omniauth_block_auto_created_users'] = false
gitlab_rails['omniauth_auto_link_user'] = ['openid_connect']

gitlab_rails['omniauth_providers'] = [
  {
    'name' => 'openid_connect',
    'label' => 'Kanidm SSO',
    'args' => {
      'name' => 'openid_connect',
      'scope' => ['openid', 'profile', 'email', 'groups'],
      'response_type' => 'code',
      'issuer' => 'https://idm.example.com/oauth2/openid/gitlab_oidc',
      'discovery' => true,
      'client_auth_method' => 'basic',
      'uid_field' => 'preferred_username',
      'client_options' => {
        'identifier' => 'your-client-id',
        'secret' => 'your-client-secret',
        'redirect_uri' => 'https://gitlab.example.com/users/auth/openid_connect/callback'
      }
    }
  }
]

# Group sync
gitlab_rails['omniauth_sync_profile_from_provider'] = ['openid_connect']
gitlab_rails['omniauth_sync_profile_attributes'] = ['name', 'email']
```

### Proxmox OAuth2/OIDC

```bash
# Register Proxmox OAuth2 client
kanidm oauth2 create proxmox_oidc "Proxmox VE SSO" \
  --origin https://proxmox.example.com:8006

# Add redirect URI
kanidm oauth2 add-redirect-url proxmox_oidc \
  https://proxmox.example.com:8006

# Enable scopes
kanidm oauth2 enable-scope proxmox_oidc openid email profile

# Map groups for authorization
kanidm oauth2 create-scope-map proxmox_oidc groups \
  proxmox_admins proxmox_operators

# Get credentials
kanidm oauth2 show-basic-secret proxmox_oidc
```

```bash
# Proxmox configuration (via CLI or Web UI)
pveum realm add kanidm --type openid \
  --issuer-url https://idm.example.com/oauth2/openid/proxmox_oidc \
  --client-id your-client-id \
  --client-key your-client-secret \
  --username-claim preferred_username \
  --scopes "openid email profile" \
  --prompt login

# Create Proxmox groups
pveum group add proxmox_admins -comment "Administrators from Kanidm"
pveum group add proxmox_operators -comment "Operators from Kanidm"

# Set permissions
pveum acl modify / -group proxmox_admins -role Administrator
pveum acl modify / -group proxmox_operators -role PVEVMAdmin
```

### Kubernetes OIDC

```bash
# Register Kubernetes OAuth2 client
kanidm oauth2 create k8s_oidc "Kubernetes OIDC" \
  --origin https://k8s.example.com

# For kubectl plugins, add localhost callback
kanidm oauth2 add-redirect-url k8s_oidc http://localhost:8000
kanidm oauth2 add-redirect-url k8s_oidc http://localhost:18000

# Enable PKCE (required for kubectl plugins)
kanidm oauth2 enable-pkce k8s_oidc

# Enable scopes
kanidm oauth2 enable-scope k8s_oidc openid email profile groups

# Map groups to claims
kanidm oauth2 create-scope-map k8s_oidc groups \
  k8s_admins k8s_developers k8s_viewers

# Get credentials
kanidm oauth2 show-basic-secret k8s_oidc
```

```yaml
# kube-apiserver configuration
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
  - command:
    - kube-apiserver
    - --oidc-issuer-url=https://idm.example.com/oauth2/openid/k8s_oidc
    - --oidc-client-id=your-client-id
    - --oidc-username-claim=preferred_username
    - --oidc-groups-claim=groups
    - --oidc-ca-file=/etc/kubernetes/pki/ca.crt
```

```yaml
# ClusterRoleBinding for Kanidm groups
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kanidm-cluster-admins
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: Group
  name: k8s_admins
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kanidm-developers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: edit
subjects:
- kind: Group
  name: k8s_developers
  apiGroup: rbac.authorization.k8s.io
```

### Authentik Integration (Forward Auth)

```bash
# Register Authentik OAuth2 client
kanidm oauth2 create authentik_oidc "Authentik SSO Provider" \
  --origin https://authentik.example.com

# Add redirect URI
kanidm oauth2 add-redirect-url authentik_oidc \
  https://authentik.example.com/source/oauth/callback/kanidm/

# Enable scopes
kanidm oauth2 enable-scope authentik_oidc openid email profile groups

# Get credentials
kanidm oauth2 show-basic-secret authentik_oidc
```

---

## RADIUS Integration

### UniFi Network RADIUS

```bash
# Create RADIUS client for UniFi controller
kanidm radius create unifi_controller "UniFi Network Controller" \
  --address 10.0.1.10

# Generate strong shared secret
kanidm radius generate-secret unifi_controller
# Output: abc123def456... (example - use actual output)

# Create RADIUS access group
kanidm group create wifi_users "Wireless Network Users"
kanidm group add-members wifi_users alice bob charlie

# Associate group with RADIUS client
kanidm radius add-group unifi_controller wifi_users
```

**UniFi Controller Configuration:**
1. Navigate to Settings → Profiles → RADIUS
2. Create New RADIUS Profile:
   - Name: Kanidm RADIUS
   - Auth Servers:
     - IP: idm.example.com
     - Port: 1812
     - Shared Secret: [from generate-secret above]
3. Apply to SSID:
   - Settings → WiFi → Edit SSID
   - Security: WPA2 Enterprise
   - RADIUS Profile: Kanidm RADIUS

### pfSense/OPNsense VPN RADIUS

```bash
# Create RADIUS client for pfSense
kanidm radius create pfsense_vpn "pfSense VPN Server" \
  --address 10.0.1.1

# Generate shared secret
kanidm radius generate-secret pfsense_vpn

# Create VPN users group
kanidm group create vpn_users "VPN Access Users"
kanidm group add-members vpn_users alice dave eve

# Associate with RADIUS
kanidm radius add-group pfsense_vpn vpn_users
```

**pfSense Configuration:**
1. System → User Manager → Authentication Servers
2. Add Server:
   - Type: RADIUS
   - Hostname: idm.example.com
   - Shared Secret: [from generate-secret]
   - Services: Authentication and Accounting
   - Auth Port: 1812
   - Acct Port: 1813
3. VPN → OpenVPN → Edit Server
   - Backend for authentication: Kanidm RADIUS

### MikroTik Router RADIUS

```bash
# Create RADIUS client for MikroTik
kanidm radius create mikrotik_router "MikroTik Router" \
  --address 10.0.1.254

# Generate shared secret
kanidm radius generate-secret mikrotik_router

# Create network admin group
kanidm group create network_admins "Network Device Administrators"
kanidm group add-members network_admins alice frank

# Associate with RADIUS
kanidm radius add-group mikrotik_router network_admins
```

**MikroTik Configuration:**
```
/radius
add address=idm.example.com secret="your-shared-secret" service=login

/user aaa
set use-radius=yes
```

### Cisco Switch RADIUS

```bash
# Create RADIUS client for Cisco switches
kanidm radius create cisco_switches "Cisco Switch Fleet" \
  --address 10.0.2.0/24  # Can use CIDR for multiple devices

# Generate shared secret
kanidm radius generate-secret cisco_switches

# Create network operator groups
kanidm group create network_operators "Network Operators (Read-Only)"
kanidm group create network_admins "Network Administrators (Full Access)"

# Associate with RADIUS
kanidm radius add-group cisco_switches network_operators
kanidm radius add-group cisco_switches network_admins
```

**Cisco IOS Configuration:**
```
aaa new-model
!
radius server KANIDM
 address ipv4 idm.example.com auth-port 1812 acct-port 1813
 key your-shared-secret
!
aaa group server radius KANIDM_GROUP
 server name KANIDM
!
aaa authentication login default group KANIDM_GROUP local
aaa authorization exec default group KANIDM_GROUP local
aaa accounting exec default start-stop group KANIDM_GROUP
!
line vty 0 4
 login authentication default
```

---

## PAM Integration

### Ubuntu/Debian PAM Setup

```bash
# Install Kanidm PAM/NSS packages
apt update
apt install kanidm-unixd kanidm-clients

# Configure Kanidm client
cat > /etc/kanidm/config <<EOF
uri = "https://idm.example.com"
verify_ca = true
verify_hostnames = true
EOF

# Enable and start kanidm-unixd
systemctl enable kanidm-unixd
systemctl start kanidm-unixd

# Test connection
kanidm login --name alice
kanidm whoami

# Configure NSS to use Kanidm
# Edit /etc/nsswitch.conf
passwd:         files kanidm systemd
group:          files kanidm systemd
shadow:         files kanidm

# Configure PAM for authentication
# /etc/pam.d/common-auth
auth    [success=2 default=ignore]      pam_kanidm.so ignore_unknown_user
auth    [success=1 default=ignore]      pam_unix.so nullok_secure try_first_pass
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so

# /etc/pam.d/common-account
account [success=1 default=ignore]      pam_kanidm.so ignore_unknown_user
account requisite                       pam_deny.so
account required                        pam_permit.so

# /etc/pam.d/common-session
session optional                        pam_kanidm.so
session required                        pam_unix.so
session optional                        pam_systemd.so

# /etc/pam.d/common-password
password [success=2 default=ignore]     pam_kanidm.so ignore_unknown_user
password [success=1 default=ignore]     pam_unix.so obscure sha512
password requisite                      pam_deny.so
password required                       pam_permit.so
```

### RHEL/CentOS/Rocky PAM Setup

```bash
# Install Kanidm packages
dnf install kanidm-unixd kanidm-clients

# Configure client
cat > /etc/kanidm/config <<EOF
uri = "https://idm.example.com"
verify_ca = true
verify_hostnames = true
EOF

# Enable kanidm-unixd
systemctl enable --now kanidm-unixd

# Configure NSS
# /etc/nsswitch.conf
passwd:     files kanidm sss systemd
group:      files kanidm sss systemd
shadow:     files kanidm sss

# Use authselect for PAM configuration (RHEL 8+)
authselect select custom-kanidm --force

# Or manually configure /etc/pam.d/system-auth
auth        sufficient    pam_kanidm.so ignore_unknown_user
auth        sufficient    pam_unix.so try_first_pass
auth        required      pam_deny.so

account     sufficient    pam_kanidm.so ignore_unknown_user
account     required      pam_unix.so

session     optional      pam_kanidm.so
session     required      pam_unix.so
```

### sudo Integration

```bash
# Configure sudo to use Kanidm groups
# /etc/sudoers.d/kanidm-groups
%sudo_admins    ALL=(ALL:ALL) ALL
%sudo_operators ALL=(ALL) NOPASSWD: /usr/sbin/systemctl, /usr/bin/journalctl

# Create groups in Kanidm
kanidm group create sudo_admins "Sudo Administrators"
kanidm group create sudo_operators "Limited Sudo Operators"

# Add users to groups
kanidm group add-members sudo_admins alice
kanidm group add-members sudo_operators bob

# Enable POSIX for groups (required for sudo)
kanidm group posix set sudo_admins --gidnumber 60000
kanidm group posix set sudo_operators --gidnumber 60001

# Test sudo access
su - alice
sudo -l  # Should show ALL permissions
```

### Home Directory Creation

```bash
# Configure PAM to create home directories
# Add to /etc/pam.d/common-session (Debian/Ubuntu)
# Or /etc/pam.d/system-auth (RHEL/CentOS)
session required    pam_mkhomedir.so skel=/etc/skel/ umask=0022

# Set default shell and home path in Kanidm
kanidm person posix set alice --shell /bin/bash
kanidm person posix set-attr alice loginShell /bin/bash

# Test login
su - alice
pwd  # Should show /home/alice
```

---

## SSH Key Management

### SSH Key Distribution via Kanidm

```bash
# User generates SSH key pair
ssh-keygen -t ed25519 -C "alice@example.com"

# User adds public key to Kanidm
kanidm person ssh add-publickey alice "work-laptop" \
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbc123def456... alice@laptop"

# Add additional keys
kanidm person ssh add-publickey alice "home-desktop" \
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhi789jkl012... alice@desktop"

# List SSH keys
kanidm person ssh list-publickeys alice

# Remove a key
kanidm person ssh delete-publickey alice "work-laptop"
```

### SSH Server Configuration

```bash
# Install kanidm-ssh on target servers
apt install kanidm-ssh  # Debian/Ubuntu
dnf install kanidm-ssh  # RHEL/CentOS

# Configure SSH to use Kanidm for authorized keys
# /etc/ssh/sshd_config
AuthorizedKeysCommand /usr/bin/kanidm_ssh_authorizedkeys %u
AuthorizedKeysCommandUser nobody
PubkeyAuthentication yes

# Restart SSH
systemctl restart sshd

# Configure kanidm-ssh client
cat > /etc/kanidm/config <<EOF
uri = "https://idm.example.com"
verify_ca = true
verify_hostnames = true
EOF

# Test SSH key retrieval
/usr/bin/kanidm_ssh_authorizedkeys alice
# Should output alice's SSH public keys
```

### SSH Certificate Authority (Advanced)

```bash
# Generate SSH CA in Kanidm (if supported)
kanidm ssh ca init

# Sign user SSH certificate
kanidm ssh ca sign alice --principals alice,admin --validity 1d

# Configure SSH server to trust CA
# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/kanidm_ca.pub

# Extract CA public key
kanidm ssh ca get-public > /etc/ssh/kanidm_ca.pub

# Restart SSH
systemctl restart sshd
```

---

## Kubernetes Integration

### Complete Kubernetes OIDC Example

```bash
# Create Kubernetes groups
kanidm group create k8s_admins "Kubernetes Cluster Administrators"
kanidm group create k8s_developers "Kubernetes Developers"
kanidm group create k8s_viewers "Kubernetes Read-Only Users"

# Add users
kanidm group add-members k8s_admins alice
kanidm group add-members k8s_developers bob charlie
kanidm group add-members k8s_viewers dave

# Register OIDC client (from earlier)
# Already configured OAuth2 client "k8s_oidc"
```

**kubectl Configuration with kubelogin:**

```bash
# Install kubelogin (kubectl OIDC plugin)
# https://github.com/int128/kubelogin
brew install int128/kubelogin/kubelogin  # macOS
# Or download from releases

# Configure kubectl context
kubectl config set-credentials kanidm-oidc \
  --exec-api-version=client.authentication.k8s.io/v1beta1 \
  --exec-command=kubectl \
  --exec-arg=oidc-login \
  --exec-arg=get-token \
  --exec-arg=--oidc-issuer-url=https://idm.example.com/oauth2/openid/k8s_oidc \
  --exec-arg=--oidc-client-id=your-client-id \
  --exec-arg=--oidc-client-secret=your-client-secret

# Set context
kubectl config set-context kanidm-k8s \
  --cluster=your-cluster \
  --user=kanidm-oidc

kubectl config use-context kanidm-k8s

# First login (opens browser)
kubectl get pods
```

---

## Application Examples

### Apache Web Server Authentication

```bash
# Install mod_auth_openidc
apt install libapache2-mod-auth-openidc

# Register OAuth2 client
kanidm oauth2 create apache_oidc "Apache Web Server" \
  --origin https://web.example.com

kanidm oauth2 add-redirect-url apache_oidc \
  https://web.example.com/redirect_uri

kanidm oauth2 enable-scope apache_oidc openid email profile
```

```apache
# /etc/apache2/sites-available/secure.conf
<VirtualHost *:443>
    ServerName web.example.com

    OIDCProviderMetadataURL https://idm.example.com/oauth2/openid/apache_oidc/.well-known/openid-configuration
    OIDCClientID your-client-id
    OIDCClientSecret your-client-secret
    OIDCRedirectURI https://web.example.com/redirect_uri
    OIDCCryptoPassphrase random-secret-phrase

    <Location /secure>
        AuthType openid-connect
        Require valid-user
    </Location>

    <Location /admin>
        AuthType openid-connect
        Require claim groups:admins
    </Location>
</VirtualHost>
```

### Nginx with oauth2-proxy

```bash
# Register OAuth2 client
kanidm oauth2 create oauth2_proxy "OAuth2 Proxy" \
  --origin https://auth.example.com

kanidm oauth2 add-redirect-url oauth2_proxy \
  https://auth.example.com/oauth2/callback

kanidm oauth2 enable-scope oauth2_proxy openid email profile groups
```

```yaml
# docker-compose.yml
version: '3'
services:
  oauth2-proxy:
    image: quay.io/oauth2-proxy/oauth2-proxy:latest
    command:
      - --provider=oidc
      - --oidc-issuer-url=https://idm.example.com/oauth2/openid/oauth2_proxy
      - --client-id=your-client-id
      - --client-secret=your-client-secret
      - --redirect-url=https://auth.example.com/oauth2/callback
      - --cookie-secret=random-32-char-secret
      - --email-domain=*
      - --upstream=http://app:8080
      - --http-address=0.0.0.0:4180
    ports:
      - "4180:4180"
```

This integration guide provides production-ready examples for common Kanidm integrations. Always test configurations in non-production environments first and follow security best practices.
