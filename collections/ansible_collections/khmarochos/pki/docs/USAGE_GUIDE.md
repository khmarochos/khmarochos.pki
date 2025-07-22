# khmarochos.pki Usage Guide

This comprehensive guide covers common use cases, best practices, and advanced configurations for the khmarochos.pki Ansible collection.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Common Use Cases](#common-use-cases)
3. [Advanced Configurations](#advanced-configurations)
4. [Integration Patterns](#integration-patterns)
5. [Automation Workflows](#automation-workflows)
6. [Performance Optimization](#performance-optimization)
7. [Troubleshooting Guide](#troubleshooting-guide)

## Getting Started

### Basic PKI Setup

The simplest PKI setup involves creating a root CA and an intermediate CA:

```yaml
---
- name: Basic PKI Setup
  hosts: localhost
  gather_facts: no
  vars:
    pki_config:
      __propagated:
        global_root_directory: "/opt/pki"
        domain: "example.com"
        certificate_subject_country_name: "US"
        certificate_subject_organization_name: "Example Organization"
        private_key_passphrase_random: true
      root:
        __parameters:
          name: "Example Root CA"
          private_key_encrypted: true
          private_key_size: 4096
          certificate_term: 7300
        intermediate:
        __parameters:
          name: "Example Intermediate CA"
          default: true
          private_key_encrypted: true
          certificate_term: 3650

  tasks:
    - name: Initialize PKI infrastructure
      khmarochos.pki.init_pki:
        pki_ca_cascade: "{{ pki_config }}"

    - name: Issue first certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "my-first-cert"
          certificate_type: "SERVER"
          certificate_subject_common_name: "app.example.com"
          certificate_term: 365
```

### Understanding the Configuration Structure

The PKI configuration uses a hierarchical structure:

- `__propagated`: Global settings inherited by all CAs and certificates
- `__parameters`: CA-specific settings that override global defaults
- Variable interpolation: `${variable_name}` references values from __propagated or __parameters

## Common Use Cases

### 1. Web Server Certificates

#### Single Domain Certificate

```yaml
- name: Issue single domain certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_config }}"
    ca_nickname: "root/intermediate"
    certificate_parameters:
      nickname: "webserver"
      certificate_type: "SERVER"
      certificate_subject_common_name: "www.example.com"
      certificate_term: 365
      private_key_size: 2048
```

#### Wildcard Certificate

```yaml
- name: Issue wildcard certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_config }}"
    ca_nickname: "root/intermediate"
    certificate_parameters:
      nickname: "wildcard"
      certificate_type: "SERVER"
      certificate_subject_common_name: "*.example.com"
      certificate_subject_alternative_names:
        - "DNS:*.example.com"
        - "DNS:example.com"
      certificate_term: 365
```

#### Multi-Domain (SAN) Certificate

```yaml
- name: Issue multi-domain certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_config }}"
    ca_nickname: "root/intermediate"
    certificate_parameters:
      nickname: "multi-domain"
      certificate_type: "SERVER"
      certificate_subject_common_name: "www.example.com"
      certificate_subject_alternative_names:
        - "DNS:www.example.com"
        - "DNS:api.example.com"
        - "DNS:admin.example.com"
        - "DNS:*.app.example.com"
        - "IP:192.168.1.100"
        - "IP:10.0.0.50"
      certificate_term: 365
```

### 2. Client Authentication Certificates

#### User Certificate

```yaml
- name: Issue user certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_config }}"
    ca_nickname: "client"
    certificate_parameters:
      nickname: "john-doe"
      certificate_type: "CLIENT"
      certificate_subject_common_name: "john.doe@example.com"
      certificate_subject_email_address: "john.doe@example.com"
      certificate_subject_organizational_unit_name: "Engineering"
      certificate_term: 730  # 2 years
      private_key_encrypted: true
      private_key_passphrase_random: true
```

#### Service Account Certificate

```yaml
- name: Issue service account certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_config }}"
    ca_nickname: "root/services"
    certificate_parameters:
      nickname: "api-service"
      certificate_type: "CLIENT"
      certificate_subject_common_name: "api-service@example.com"
      certificate_subject_organizational_unit_name: "Services"
      certificate_term: 365
      private_key_encrypted: false  # For automated systems
```

### 3. Kubernetes Integration

#### Complete Kubernetes PKI

```yaml
---
- name: Kubernetes PKI Setup
  hosts: localhost
  vars:
    k8s_pki_config:
      __propagated:
        global_root_directory: "/etc/kubernetes/pki"
        certificate_subject_organization_name: "kubernetes"
        private_key_passphrase_random: false  # K8s needs unencrypted keys
      root:
        __parameters:
          name: "Kubernetes CA"
          certificate_term: 3650
      root/etcd:
        __parameters:
          name: "etcd CA"
          certificate_term: 3650
      root/front-proxy:
        __parameters:
          name: "Front Proxy CA"
          certificate_term: 3650

  tasks:
    - name: Initialize Kubernetes PKI
      khmarochos.pki.init_pki:
        pki_ca_cascade: "{{ k8s_pki_config }}"

    - name: Issue API Server certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ k8s_pki_config }}"
        ca_nickname: "root"
        certificate_parameters:
          nickname: "apiserver"
          certificate_type: "SERVER"
          certificate_subject_common_name: "kube-apiserver"
          certificate_subject_alternative_names:
            - "DNS:kubernetes"
            - "DNS:kubernetes.default"
            - "DNS:kubernetes.default.svc"
            - "DNS:kubernetes.default.svc.cluster.local"
            - "DNS:master.example.com"
            - "IP:10.96.0.1"  # Service cluster IP
            - "IP:10.0.0.10"  # Master node IP
          certificate_term: 365

    - name: Issue etcd server certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ k8s_pki_config }}"
        ca_nickname: "root/etcd"
        certificate_parameters:
          nickname: "etcd-server"
          certificate_type: "SERVER"
          certificate_subject_common_name: "etcd"
          certificate_subject_alternative_names:
            - "DNS:etcd"
            - "DNS:localhost"
            - "IP:127.0.0.1"
            - "IP:10.0.0.10"
          certificate_term: 365
```

#### Generate Kubernetes TLS Secrets

```yaml
- name: Create Kubernetes TLS secret
  block:
    - name: Issue certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "ingress-tls"
          certificate_type: "SERVER"
          certificate_subject_common_name: "*.apps.example.com"
          certificate_subject_alternative_names:
            - "DNS:*.apps.example.com"
            - "DNS:apps.example.com"
      register: ingress_cert

    - name: Create TLS secret
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: v1
          kind: Secret
          metadata:
            name: ingress-tls
            namespace: ingress-nginx
          type: kubernetes.io/tls
          data:
            tls.crt: "{{ lookup('file', ingress_cert.result.certificate.file) | b64encode }}"
            tls.key: "{{ lookup('file', ingress_cert.result.private_key.file) | b64encode }}"
```

### 4. Multi-Environment PKI

```yaml
---
- name: Multi-Environment PKI
  hosts: localhost
  vars:
    environments:
      production:
        base_domain: "prod.example.com"
        ca_term: 3650
        cert_term: 365
        key_size: 4096
      staging:
        base_domain: "stage.example.com"
        ca_term: 1825
        cert_term: 90
        key_size: 2048
      development:
        base_domain: "dev.example.com"
        ca_term: 365
        cert_term: 30
        key_size: 2048

  tasks:
    - name: Setup PKI for each environment
      include_tasks: setup_environment_pki.yml
      vars:
        env_name: "{{ item.key }}"
        env_config: "{{ item.value }}"
      loop: "{{ environments | dict2items }}"

# setup_environment_pki.yml
---
- name: Initialize {{ env_name }} PKI
  khmarochos.pki.init_pki:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/opt/pki/{{ env_name }}"
        domain: "{{ env_config.base_domain }}"
        certificate_subject_organization_name: "Example Corp"
        certificate_subject_organizational_unit_name: "{{ env_name | title }}"
      root:
        __parameters:
          name: "{{ env_name | title }} Root CA"
          private_key_encrypted: true
          private_key_size: "{{ env_config.key_size }}"
          certificate_term: "{{ env_config.ca_term }}"
        intermediate:
        __parameters:
          name: "{{ env_name | title }} Intermediate CA"
          default: true
          certificate_term: "{{ env_config.ca_term // 2 }}"
```

## Advanced Configurations

### 1. High-Security PKI with HSM

```yaml
---
- name: High-Security PKI Setup
  hosts: localhost
  vars:
    high_security_pki:
      __propagated:
        global_root_directory: "/opt/pki/secure"
        certificate_subject_organization_name: "Secure Corp"
        # Enhanced security settings
        private_key_algorithm: "RSA"
        private_key_size: 4096
        private_key_encrypted: true
        private_key_passphrase_random: true
        private_key_passphrase_length: 64
        certificate_digest_algorithm: "sha512"
      root:
        __parameters:
          name: "Secure Root CA"
          certificate_term: 7300
          # Root CA should be offline after creation
          certificate_crl_distribution_points:
            - "http://crl.securecorp.com/root-ca.crl"
          certificate_authority_information_access:
            - "OCSP;URI:http://ocsp.securecorp.com/root"
      root/issuing:
        __parameters:
          name: "Secure Issuing CA"
          certificate_term: 1825
          default: true
          certificate_crl_distribution_points:
            - "http://crl.securecorp.com/issuing-ca.crl"

  tasks:
    - name: Initialize high-security PKI
      khmarochos.pki.init_pki:
        pki_ca_cascade: "{{ high_security_pki }}"
      
    - name: Backup root CA private key
      archive:
        path: "/opt/pki/secure/root/private"
        dest: "/secure-backup/root-ca-{{ ansible_date_time.epoch }}.tar.gz"
        format: gz
        mode: '0600'
      
    - name: Remove root CA private key (for offline storage)
      file:
        path: "/opt/pki/secure/root/private/CA/ca.key"
        state: absent
```

### 2. Cross-Signed Certificates

```yaml
---
- name: Cross-Signed Certificate Setup
  hosts: localhost
  tasks:
    - name: Create primary PKI
      khmarochos.pki.init_pki:
        pki_ca_cascade:
          __propagated:
            global_root_directory: "/opt/pki/primary"
            certificate_subject_organization_name: "Primary Org"
          root:
            __parameters:
              name: "Primary Root CA"
            intermediate:
            __parameters:
              name: "Primary Intermediate CA"
              default: true

    - name: Create secondary PKI
      khmarochos.pki.init_pki:
        pki_ca_cascade:
          __propagated:
            global_root_directory: "/opt/pki/secondary"
            certificate_subject_organization_name: "Secondary Org"
          root:
            __parameters:
              name: "Secondary Root CA"
            intermediate:
            __parameters:
              name: "Secondary Intermediate CA"
              default: true

    # Cross-signing would require custom tasks here
    # This is a placeholder for the concept
```

### 3. Certificate Templates

```yaml
---
- name: Certificate Templates
  hosts: localhost
  vars:
    cert_templates:
      web_server:
        certificate_type: "SERVER"
        certificate_term: 365
        private_key_size: 2048
        private_key_encrypted: false
        subject_fields:
          certificate_subject_organizational_unit_name: "Web Services"
      
      api_server:
        certificate_type: "SERVER"
        certificate_term: 90  # Short-lived
        private_key_size: 4096
        private_key_encrypted: true
        subject_fields:
          certificate_subject_organizational_unit_name: "API Services"
      
      user_auth:
        certificate_type: "CLIENT"
        certificate_term: 730
        private_key_size: 2048
        private_key_encrypted: true
        subject_fields:
          certificate_subject_organizational_unit_name: "Users"

  tasks:
    - name: Issue certificates using templates
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "{{ item.name }}"
          certificate_type: "{{ cert_templates[item.template].certificate_type }}"
          certificate_term: "{{ cert_templates[item.template].certificate_term }}"
          certificate_subject_common_name: "{{ item.common_name }}"
          certificate_subject_alternative_names: "{{ item.sans | default([]) }}"
          private_key_size: "{{ cert_templates[item.template].private_key_size }}"
          private_key_encrypted: "{{ cert_templates[item.template].private_key_encrypted }}"
          certificate_subject_organizational_unit_name: "{{ cert_templates[item.template].subject_fields.certificate_subject_organizational_unit_name }}"
      loop:
        - name: "web-prod"
          template: "web_server"
          common_name: "www.example.com"
          sans:
            - "DNS:www.example.com"
            - "DNS:example.com"
        - name: "api-prod"
          template: "api_server"
          common_name: "api.example.com"
          sans:
            - "DNS:api.example.com"
            - "DNS:api-v1.example.com"
```

## Integration Patterns

### 1. CI/CD Pipeline Integration

```yaml
---
# .gitlab-ci.yml example
stages:
  - validate
  - deploy

validate_pki:
  stage: validate
  script:
    - ansible-playbook validate_pki.yml

deploy_certificates:
  stage: deploy
  script:
    - ansible-playbook deploy_certificates.yml
  only:
    - main

# validate_pki.yml
---
- name: Validate PKI Configuration
  hosts: localhost
  tasks:
    - name: Validate PKI structure
      khmarochos.pki.init_dictionary:
        pki_ca_cascade: "{{ lookup('file', 'pki_config.yml') | from_yaml }}"
      register: validation

    - name: Check for expiring certificates
      shell: |
        find /opt/pki -name "*.crt" -type f -exec \
          openssl x509 -checkend 2592000 -noout -in {} \; \
          -print 2>&1 | grep -B1 "will expire" || true
      register: expiring_certs

    - name: Fail if certificates are expiring
      fail:
        msg: "Certificates expiring soon: {{ expiring_certs.stdout }}"
      when: expiring_certs.stdout != ""
```

### 2. HashiCorp Vault Integration

```yaml
---
- name: Vault PKI Integration
  hosts: localhost
  vars:
    vault_addr: "https://vault.example.com:8200"
    
  tasks:
    - name: Issue certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "vault-cert"
          certificate_type: "SERVER"
          certificate_subject_common_name: "app.example.com"
          certificate_term: 90
      register: cert_result

    - name: Store in Vault
      uri:
        url: "{{ vault_addr }}/v1/secret/data/certificates/{{ cert_result.result.certificate.nickname }}"
        method: POST
        headers:
          X-Vault-Token: "{{ vault_token }}"
        body_format: json
        body:
          data:
            certificate: "{{ lookup('file', cert_result.result.certificate.file) }}"
            private_key: "{{ lookup('file', cert_result.result.private_key.file) }}"
            chain: "{{ lookup('file', cert_result.result.certificate.chain_file) }}"
            metadata:
              issued_at: "{{ cert_result.result.certificate.not_before }}"
              expires_at: "{{ cert_result.result.certificate.not_after }}"
              issuer: "{{ cert_result.result.certificate.issuer }}"
```

### 3. Monitoring and Alerting

```yaml
---
- name: PKI Monitoring Setup
  hosts: localhost
  vars:
    alert_days_before_expiry: 30
    alert_email: "pki-admin@example.com"
    
  tasks:
    - name: Check certificate expiration
      shell: |
        find /opt/pki -name "*.crt" -type f | while read cert; do
          subject=$(openssl x509 -subject -noout -in "$cert" | sed 's/subject=//')
          enddate=$(openssl x509 -enddate -noout -in "$cert" | sed 's/notAfter=//')
          days_left=$(( ($(date -d "$enddate" +%s) - $(date +%s)) / 86400 ))
          
          if [ $days_left -lt {{ alert_days_before_expiry }} ]; then
            echo "EXPIRING: $cert (Subject: $subject) expires in $days_left days"
          fi
        done
      register: expiring_certs
      changed_when: false

    - name: Send alert email
      mail:
        to: "{{ alert_email }}"
        subject: "PKI Alert: Certificates Expiring Soon"
        body: |
          The following certificates will expire within {{ alert_days_before_expiry }} days:
          
          {{ expiring_certs.stdout }}
          
          Please renew these certificates as soon as possible.
      when: expiring_certs.stdout != ""

    - name: Export metrics for Prometheus
      copy:
        content: |
          # HELP pki_certificate_expiry_days Days until certificate expires
          # TYPE pki_certificate_expiry_days gauge
          {% for cert in certificates %}
          pki_certificate_expiry_days{nickname="{{ cert.nickname }}",cn="{{ cert.cn }}"} {{ cert.days_left }}
          {% endfor %}
        dest: /var/lib/prometheus/node_exporter/pki_metrics.prom
```

## Automation Workflows

### 1. Automated Certificate Renewal

```yaml
---
- name: Automated Certificate Renewal
  hosts: localhost
  vars:
    renewal_threshold_days: 30
    
  tasks:
    - name: Get all certificates
      find:
        paths: "/opt/pki"
        patterns: "*.crt"
        recurse: yes
        excludes: "*/CA/*"  # Exclude CA certificates
      register: all_certs

    - name: Check each certificate
      include_tasks: check_and_renew_cert.yml
      vars:
        cert_path: "{{ item.path }}"
      loop: "{{ all_certs.files }}"

# check_and_renew_cert.yml
---
- name: Get certificate info
  openssl_certificate_info:
    path: "{{ cert_path }}"
  register: cert_info

- name: Calculate days until expiry
  set_fact:
    days_until_expiry: "{{ ((cert_info.not_after | to_datetime('%Y%m%d%H%M%SZ')) - (now | to_datetime('%Y%m%d%H%M%SZ'))) | total_seconds / 86400 | int }}"

- name: Renew if needed
  when: days_until_expiry | int <= renewal_threshold_days
  block:
    - name: Extract certificate details
      set_fact:
        cert_nickname: "{{ cert_path | basename | regex_replace('\\.crt$', '') }}"
        cert_ca_path: "{{ cert_path | dirname | regex_replace('/certs.*', '') }}"

    - name: Determine CA nickname
      set_fact:
        ca_nickname: "{{ cert_ca_path | regex_replace('^.*/pki/', '') }}"

    - name: Renew certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "{{ ca_nickname }}"
        certificate_parameters:
          nickname: "{{ cert_nickname }}"
          certificate_type: "{{ cert_info.extensions.keyUsage }}"  # Simplified
          certificate_subject_common_name: "{{ cert_info.subject.commonName }}"
          certificate_subject_alternative_names: "{{ cert_info.subject_alt_name }}"
          certificate_term: 365
        save_forced: true
      register: renewal_result

    - name: Notify about renewal
      debug:
        msg: "Renewed certificate: {{ cert_nickname }} (was expiring in {{ days_until_expiry }} days)"
```

### 2. Certificate Distribution

```yaml
---
- name: Certificate Distribution Workflow
  hosts: all
  vars:
    pki_distribution_map:
      web_servers:
        - nickname: "web-wildcard"
          deploy_to: "/etc/nginx/ssl/"
          restart_service: "nginx"
      app_servers:
        - nickname: "api-cert"
          deploy_to: "/opt/app/certs/"
          restart_service: "application"
      
  tasks:
    - name: Determine server role
      set_fact:
        server_role: "{{ group_names | select('match', '^(web|app)_servers$') | first }}"

    - name: Deploy certificates
      include_tasks: deploy_cert.yml
      vars:
        cert_config: "{{ item }}"
      loop: "{{ pki_distribution_map[server_role] }}"
      when: server_role in pki_distribution_map

# deploy_cert.yml
---
- name: Ensure certificate directory exists
  file:
    path: "{{ cert_config.deploy_to }}"
    state: directory
    mode: '0755'

- name: Copy certificate files
  copy:
    src: "{{ item }}"
    dest: "{{ cert_config.deploy_to }}{{ item | basename }}"
    mode: '0644'
  loop:
    - "/opt/pki/{{ ca_path }}/certs/{{ cert_config.nickname }}.crt"
    - "/opt/pki/{{ ca_path }}/certs/CA/chain.crt"
  register: cert_copy

- name: Copy private key
  copy:
    src: "/opt/pki/{{ ca_path }}/private/{{ cert_config.nickname }}.key"
    dest: "{{ cert_config.deploy_to }}{{ cert_config.nickname }}.key"
    mode: '0600'
    owner: "{{ cert_config.key_owner | default('root') }}"
    group: "{{ cert_config.key_group | default('root') }}"
  register: key_copy

- name: Restart service if certificate changed
  systemd:
    name: "{{ cert_config.restart_service }}"
    state: restarted
  when: cert_copy.changed or key_copy.changed
```

## Performance Optimization

### 1. Parallel Certificate Generation

```yaml
---
- name: Parallel Certificate Generation
  hosts: localhost
  vars:
    certificates_to_generate:
      - nickname: "web-01"
        common_name: "web01.example.com"
      - nickname: "web-02"
        common_name: "web02.example.com"
      - nickname: "web-03"
        common_name: "web03.example.com"
      # ... many more certificates
      
  tasks:
    - name: Generate certificates in parallel
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "{{ item.nickname }}"
          certificate_type: "SERVER"
          certificate_subject_common_name: "{{ item.common_name }}"
          certificate_term: 365
      loop: "{{ certificates_to_generate }}"
      async: 300  # 5 minute timeout
      poll: 0     # Don't wait
      register: cert_jobs

    - name: Wait for all certificates
      async_status:
        jid: "{{ item.ansible_job_id }}"
      register: job_result
      until: job_result.finished
      delay: 2
      retries: 150
      loop: "{{ cert_jobs.results }}"
```

### 2. Caching PKI Configuration

```yaml
---
- name: Cached PKI Operations
  hosts: localhost
  tasks:
    - name: Load and cache PKI configuration
      khmarochos.pki.init_dictionary:
        pki_ca_cascade: "{{ pki_config }}"
      register: pki_dict
      run_once: true

    - name: Store in fact cache
      set_fact:
        cached_pki_dict: "{{ pki_dict.result }}"
        cacheable: yes

    - name: Use cached configuration
      debug:
        msg: "Using CA: {{ cached_pki_dict.default_ca_nickname }}"
```

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. Permission Denied Errors

```yaml
- name: Fix PKI permissions
  hosts: localhost
  tasks:
    - name: Fix directory permissions
      file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
        recurse: yes
      loop:
        - path: "/opt/pki/*/private"
          mode: "0700"
        - path: "/opt/pki/*/certs"
          mode: "0755"
        - path: "/opt/pki/*/csr"
          mode: "0755"

    - name: Fix file permissions
      shell: |
        find /opt/pki -name "*.key" -type f -exec chmod 600 {} \;
        find /opt/pki -name "passphrase" -type f -exec chmod 600 {} \;
        find /opt/pki -name "*.crt" -type f -exec chmod 644 {} \;
        find /opt/pki -name "*.csr" -type f -exec chmod 644 {} \;
```

#### 2. Certificate Chain Validation

```yaml
- name: Validate certificate chains
  hosts: localhost
  tasks:
    - name: Validate all certificate chains
      shell: |
        for cert in $(find /opt/pki -name "*.crt" -not -path "*/CA/*"); do
          echo "Checking: $cert"
          ca_path=$(dirname $cert)/../certs/CA/ca.crt
          chain_path=$(dirname $cert)/../certs/CA/chain.crt
          
          if [ -f "$chain_path" ]; then
            openssl verify -CAfile "$chain_path" "$cert"
          else
            openssl verify -CAfile "$ca_path" "$cert"
          fi
        done
      register: validation_result

    - name: Show validation results
      debug:
        var: validation_result.stdout_lines
```

#### 3. Debug Certificate Issues

```yaml
- name: Debug certificate issues
  hosts: localhost
  vars:
    cert_to_debug: "/opt/pki/intermediate/certs/problem-cert.crt"
    
  tasks:
    - name: Get certificate details
      shell: |
        echo "=== Certificate Details ==="
        openssl x509 -in {{ cert_to_debug }} -text -noout
        
        echo -e "\n=== Certificate Dates ==="
        openssl x509 -in {{ cert_to_debug }} -dates -noout
        
        echo -e "\n=== Certificate Subject ==="
        openssl x509 -in {{ cert_to_debug }} -subject -noout
        
        echo -e "\n=== Certificate Issuer ==="
        openssl x509 -in {{ cert_to_debug }} -issuer -noout
        
        echo -e "\n=== Certificate SANs ==="
        openssl x509 -in {{ cert_to_debug }} -text -noout | grep -A1 "Subject Alternative Name"
        
        echo -e "\n=== Certificate Chain ==="
        openssl verify -CAfile $(dirname {{ cert_to_debug }})/../certs/CA/chain.crt {{ cert_to_debug }}
      register: debug_output

    - name: Display debug information
      debug:
        var: debug_output.stdout_lines
```

### Recovery Procedures

#### 1. Recover from Corrupted CA

```yaml
- name: Recover from corrupted CA
  hosts: localhost
  tasks:
    - name: Backup corrupted PKI
      archive:
        path: "/opt/pki"
        dest: "/backup/pki-corrupted-{{ ansible_date_time.epoch }}.tar.gz"
        format: gz

    - name: Restore from backup
      unarchive:
        src: "/backup/pki-good-backup.tar.gz"
        dest: "/"
        remote_src: yes

    - name: Verify restored PKI
      khmarochos.pki.init_dictionary:
        pki_ca_cascade: "{{ pki_config }}"
      register: verification

    - name: Regenerate affected certificates
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "{{ item.ca }}"
        certificate_parameters: "{{ item.params }}"
        save_forced: true
      loop: "{{ affected_certificates }}"
```

#### 2. Emergency Certificate Replacement

```yaml
- name: Emergency certificate replacement
  hosts: all
  vars:
    emergency_cert: "/tmp/emergency-cert.crt"
    emergency_key: "/tmp/emergency-cert.key"
    
  tasks:
    - name: Generate emergency self-signed certificate
      command: |
        openssl req -x509 -nodes -days 30 \
          -newkey rsa:2048 \
          -keyout {{ emergency_key }} \
          -out {{ emergency_cert }} \
          -subj "/CN={{ inventory_hostname }}/O=Emergency"
      delegate_to: localhost
      run_once: true

    - name: Deploy emergency certificate
      copy:
        src: "{{ item.src }}"
        dest: "{{ item.dest }}"
        mode: "{{ item.mode }}"
      loop:
        - src: "{{ emergency_cert }}"
          dest: "/etc/ssl/certs/emergency.crt"
          mode: "0644"
        - src: "{{ emergency_key }}"
          dest: "/etc/ssl/private/emergency.key"
          mode: "0600"

    - name: Update service configuration
      lineinfile:
        path: "/etc/nginx/sites-available/default"
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - regexp: "ssl_certificate "
          line: "    ssl_certificate /etc/ssl/certs/emergency.crt;"
        - regexp: "ssl_certificate_key "
          line: "    ssl_certificate_key /etc/ssl/private/emergency.key;"
      notify: restart nginx
```

## Best Practices Summary

1. **Security**
   - Always encrypt root CA private keys
   - Use strong passphrases (minimum 32 characters)
   - Store root CA offline after creation
   - Implement proper file permissions
   - Regular security audits

2. **Operations**
   - Automate certificate renewal
   - Monitor expiration dates
   - Maintain comprehensive backups
   - Document PKI structure
   - Test recovery procedures

3. **Performance**
   - Use parallel processing for bulk operations
   - Cache PKI configurations
   - Optimize certificate validity periods
   - Implement efficient distribution mechanisms

4. **Compliance**
   - Follow industry standards (X.509 v3)
   - Implement proper certificate lifecycles
   - Maintain audit logs
   - Regular compliance reviews

---

For more information and updates, visit the [khmarochos.pki GitHub repository](https://github.com/khmarochos/khmarochos.pki).