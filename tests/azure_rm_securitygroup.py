---
- name: Test azuzre_rm_securitygroup
  hosts: localhost
  tasks:
     - name: Remove log file
       file:
           name: azure_rm_securitygroup.log
           state: absent

     - name: Add rules
       azure_rm_securitygroup:
           resource_group: chouse
           name: nsg-001
           location: 'East US'
           rules:
               - name: test-001
                 protocol: TCP
                 source_port_range: '*' 
                 source_address_prefix: '174.109.158.0/24'
                 destination_address_prefix: '137.35.101.216/24'
                 destination_port_range: 22
                 access: Allow
                 priority: '100'
                 direction: Inbound 
               - name: test-002
                 protocol: TCP
                 source_port_range: '*' 
                 source_address_prefix: '174.109.158.0/24'
                 destination_address_prefix: '137.35.101.216/24'
                 destination_port_range: 80
                 access: Allow
                 priority: 101
                 direction: Inbound 
           state: present
       register: creation

     - name: Debug
       debug: var=creation
  
