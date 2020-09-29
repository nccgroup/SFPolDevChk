#!/usr/bin/env python3

"""
Released as open source by NCC Group Plc - https://www.nccgroup.com/

Developed by Jerome Smith, NCC Group, @exploresecurity
With thanks to Stephen Tomkinson, NCC Group, @neonbunny9

https://www.github.com/nccgroup/SFPolDevChk

Released under AGPL - refer to LICENSE for more information.
"""

import sys
import requests
from xml.etree import ElementTree
import json
from urllib.parse import urlencode, unquote
import traceback

#################
### Constants ###

VERSION = '1.0'
CONFIG_FILE_FORMAT = '''\
    {
        "hostname": "somewhere.my.salesforce.com",
        "username": "",
        "password": "",
        "token": "<optional token>"
        "debug": <optional debug level (0, 1 or 2)>
    }'''
API_VERSION = '49.0'
# Org and Profile setting names are not always identical and not all values are comparable
# The following allows Profile settings to be matched to Org equivalents
# No Org equivalent of Profile setting 'forgotPasswordRedirect' ("Don't immediately expire links in forgot password emails")
# 5 is not a documented Profile password complexity value but Any3UpperLowerCaseNumericSpecialCharacters is for Org
# 180 is not a documented Profile password expiry value but SixMonths is for Org
PROFILE_TO_ORG_PWD_POL = {
    "lockoutInterval": {
        "desc": "Lockout effective period",
        "orgTerm": "lockoutInterval",
        "values": {
            "0": "Forever",
            "15": "FifteenMinutes",
            "30": "ThirtyMinutes",
            "60": "SixtyMinutes"
            }
        },
    "maxLoginAttempts": {
        "desc": "Maximum invalid login attempts",
        "orgTerm": "maxLoginAttempts",
        "values": {
            "0": "NoLimit",
            "3": "ThreeAttempts",
            "5": "FiveAttempts",
            "10": "TenAttempts"
            }
        },
    "minimumPasswordLength": {
        "desc": "Minimum password length",
        "orgTerm": "minimumPasswordLength",
        "values": {}
        },
    "minimumPasswordLifetime": {
        "desc": "Require a minimum 1 day password lifetime",
        "orgTerm": "minimumPasswordLifetime",
        "values": {}
        },
    "obscure": {
        "desc": "Obscure secret answer for password resets",
        "orgTerm": "obscureSecretAnswer",
        "values": {}
        },
    "passwordComplexity": {
        "desc": "Password complexity requirement",
        "orgTerm": "complexity",
        "values": {
            "0": "NoRestriction",
            "1": "AlphaNumeric",
            "2": "SpecialCharacters",
            "3": "UpperLowerCaseNumeric",
            "4": "UpperLowerCaseNumericSpecialCharacters",
            "5": "Any3UpperLowerCaseNumericSpecialCharacters"
            }
        },
    "passwordExpiration": {
        "desc": "User passwords expire in",
        "orgTerm": "expiration",
        "values": {
            "0": "Never",
            "30": "ThirtyDays",
            "60": "SixtyDays",
            "90": "NinetyDays",
            "180": "SixMonths",
            "365": "OneYear"
            }
        },
    "passwordHistory": {
        "desc": "Enforce password history",
        "orgTerm": "historyRestriction",
        "values": {}
        },
    "passwordQuestion": {
        "desc": "Password question requirement",
        "orgTerm": "questionRestriction",
        "values": {
            "0": "None",
            "1": "DoesNotContainPassword"
            }
        }
    }
# Org and Profile setting names are not always identical and not all values are comparable
# The following allows Profile settings to be matched to Org equivalents
# No Org equivalent of Profile setting 'externalCommunityUserIdentityVerif' (undocumented, perhaps "Enable device activation")
# No Org equivalent of Profile setting 'sessionPersistence' ("Keep users logged in when they close the browser")
# 0 is not a documented Profile sessionTimeout value but seems to correspond to the default of TwoHours
# TwentyFourHours is not a documented Org sessionTimeout value but it's returned by the API when '24 hours' is selected
PROFILE_TO_ORG_SESS_SETTINGS = {
    "sessionTimeout": {
        "desc": "Session times out after",
        "orgTerm": "sessionTimeout",
        "values": {
            "0": "TwoHours",
            "15": "FifteenMinutes",
            "30": "ThirtyMinutes",
            "60": "SixtyMinutes",
            "120": "TwoHours",
            "240": "FourHours",
            "480": "EightHours",
            "720": "TwelveHours",
            "1440": "TwentyFourHours"
            }
        },
# These settings do not appear in the UI at a profile level and do not appear to be effective over the Organization settings:
#    "sessionTimeoutWarning": {
#        "desc": "Disable session timeout warning popup",
#        "orgTerm": "disableTimeoutWarning",
#        "values": {
#            "true": "false",
#            "false": "true"
#            }
#        }
#    "forceLogout": {
#        "desc": "Force logout on session timeout",
#        "orgTerm": "forceLogoutOnSessionTimeout",
#        "values": {}
#        },
    }

###############
### Classes ###

class SfpoldevchkError(ValueError):
    """A slightly more specific Exception class to raise"""
    pass

#################
### Functions ###

def banner():
    """Introduce yourself."""
    print("Salesforce Policy Deviation Checker")
    print("- version " + VERSION)
    print("- https://www.github.com/nccgroup/SFPolDevChk")

def error(message, exception, debug=0):
    """Handle errors with increasing amounts of output depending on 'debug' level, then exit.
    
    Arguments:
        debug -- 0 for a simple message, 1 to add exception details, 2 to output stack trace to .err file
    """
    print("\nERROR: " + message)
    print("  '" + type(exception).__name__ + "' was raised")
    if debug > 0:
        print("  - with " + str(len(exception.args)) + " argument(s):")
        for i, a in enumerate(exception.args):
            print("  [" + str(i+1) + "] " + str(a))
    if debug > 1:
        try:
            with open(sys.argv[0] + '.err', 'w') as error_file:
                traceback.print_exc(file=error_file)
        except:
            print("  ERROR: Failed to write stack trace to file")
            traceback.print_exc()
        print("  Stack trace written to " + sys.argv[0] + ".err")
    if debug < 2:
        print("To find out more, try increasing the debug level in the config file")
    exit(1)

def load_config(file):
    """Load configuration from a file so that credentials are not in the user's console history."""
    with open(file) as config_file:
        config = json.load(config_file)
    if 'hostname' in config:
        hostname = config['hostname']
    else:
        raise ValueError("No 'hostname' parameter in config file " + file)
    if 'username' in config:
        username = config['username']
    else:
        raise ValueError("No 'username' parameter in config file " + file)
    if 'password' in config:
        password = config['password']
    else:
        raise ValueError("No 'password' parameter in config file " + file)
    # token not always required
    if 'token' in config:
        token = config['token']
    else:
        token = ''
    # debug is optional
    if 'debug' in config:
        try:
            debug = int(config['debug'])
        except:
            raise TypeError("Debug value should be a number")
    else:
        debug = 0
    return (hostname, username, password, token, debug)

def call_rest_api(rest_api_url, session_id=None):
    """Call the REST API with a supplied URL and optional authentication."""
    if session_id is None:
        rest_headers = None
    else:
        rest_headers = {'Authorization': 'Bearer ' + session_id}
    response = requests.get(rest_api_url, headers=rest_headers)
    # Check for unsuccessful response
    response.raise_for_status()
    json_response = json.loads(response.text)
    return json_response

def call_rest_query_api(rest_query_api_url, session_id, query):
    """Call the REST Query API."""
    request_url = rest_query_api_url + '/?' + urlencode({"q": query})
    json_response = call_rest_api(request_url, session_id)
    return json_response['records']

def call_soap_api(soap_api_url, body, soap_action, session_id=None):
    """Call the SOAP API with a supplied URL and optional authentication."""
    xml_declaration = '<?xml version="1.0" encoding="utf-8"?>'
    if session_id is None:
        soap_header = ""
    else:
        soap_header = '''
        <soapenv:Header>
            <tns:SessionHeader>
    	    	<tns:sessionId>''' + session_id + '''</tns:sessionId>
    	    </tns:SessionHeader>
    	</soapenv:Header>
    	'''
    envelope = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://soap.sforce.com/2006/04/metadata">' + soap_header + body + '</soapenv:Envelope>'
    soap_message = xml_declaration + envelope
    http_headers = {'Content-Type': 'text/xml', 'SOAPAction': soap_action}
    response = requests.post(soap_api_url, data=soap_message, headers=http_headers)
    # Check for unsuccessful response - but not via raise_for_status() to get more debug info
    if response.status_code != 200:
        raise requests.HTTPError("Expected 200 response: got " + str(response.status_code), response.text)
    root = ElementTree.fromstring(response.text)
    return root

def call_list_metadata(metadata_url, session_id, folder, type_):
    """Call listMetadata()."""
    body = '''
        <soapenv:Body>
		    <tns:listMetadata>
		    	<tns:queries>
		    		<tns:folder>''' + folder + '''</tns:folder>
		    		<tns:type>''' + type_ + '''</tns:type>
		    	</tns:queries>
		    </tns:listMetadata>
    	</soapenv:Body>
    	'''
    list_metadata_response_element = call_soap_api(metadata_url, body, '""', session_id).find('.//{http://soap.sforce.com/2006/04/metadata}listMetadataResponse')
    if list_metadata_response_element is None:
        raise SfpoldevchkError("No listMetadata response for " + folder + "/" + type_)
    return list_metadata_response_element

def call_read_metadata(metadata_url, session_id, type_, fullnames):
    """Call readMetadata()."""
    body = '''
        <soapenv:Body>
		    <tns:readMetadata>
		    	<tns:type>''' + type_ + '''</tns:type>
		    	<tns:fullNames>''' + fullnames + '''</tns:fullNames>
		    </tns:readMetadata>
    	</soapenv:Body>
    	'''
    read_metadata_response_element = call_soap_api(metadata_url, body, '""', session_id).find('.//{http://soap.sforce.com/2006/04/metadata}readMetadataResponse')
    if read_metadata_response_element is None:
        raise SfpoldevchkError("No readMetadata response for " + type_ + "/" + fullnames)
    return read_metadata_response_element

def check_api_ver_supported(rest_api_url):
    """Check that the API version is supported by the host but, if not, don't fail."""
    supported_api_vers = call_rest_api(rest_api_url)
    # Simple substring check will suffice
    if API_VERSION not in json.dumps(supported_api_vers):
        print("Unsupported API version - this tool requires version " + API_VERSION)
        print("- let's carry on anyway but this could explain any subsequent errors")


def login(hostname, username, password, token):
    """Log in to get a session ID and the metadata URL."""
    body = '''
        <soapenv:Body>
          <n1:login xmlns:n1="urn:partner.soap.sforce.com">
            <n1:username>''' + username + '''</n1:username>
          <n1:password>''' + password + token + '''</n1:password>
        </n1:login>
        </soapenv:Body>
        '''
    login_url = 'https://' + hostname + '/services/Soap/u/' + API_VERSION
    login_response = call_soap_api(login_url, body, 'login')
    session_id_element = login_response.find('.//{urn:partner.soap.sforce.com}sessionId')
    if session_id_element is None:
        exception_message_element = login_response.find('.//{urn:fault.partner.soap.sforce.com}exceptionMessage')
        if exception_message_element is None:
            exception_message = ""
        else:
            exception_message = "\n" + exception_message_element.text
        raise SfpoldevchkError("No session ID found in login response" + exception_message)
    else:
        session_id = session_id_element.text
    metadata_url_element = login_response.find('.//{urn:partner.soap.sforce.com}metadataServerUrl')
    if metadata_url_element is None:
        raise SfpoldevchkError("No metadata endpoint URL found in login response")
    else:
        metadata_url = metadata_url_element.text
    return (session_id, metadata_url)

def get_profile_info(rest_query_api_url, session_id, metadata_url):
    """Query the REST and metadata APIs to return the core Profile info needed."""
    try:
        profiles_json = call_rest_query_api(rest_query_api_url, session_id, 'SELECT Id,Name FROM Profile')
        profiles_xml = call_list_metadata(metadata_url, session_id, 'profiles', 'Profile')
    except:
        raise SfpoldevchkError("Failed to get profile information from REST and Metadata APIs")
    profiles = []
    try:
        for p in profiles_json:
            profile = {}
            profile['Name'] = p['Name']
            profile['Fullname'] = profiles_xml.find('.//{http://soap.sforce.com/2006/04/metadata}result[{http://soap.sforce.com/2006/04/metadata}id="' + p['Id'] + '"]/{http://soap.sforce.com/2006/04/metadata}fullName').text
            profiles.append(profile)
    except:
        raise SfpoldevchkError("Failed to extract Name and/or fullName from profile information", profiles_json, ElementTree.tostring(profiles_xml))
    return profiles

def get_org_pwd_pol(metadata_url, session_id):
    """Get the Organization password policy."""
    security_settings = call_read_metadata(metadata_url, session_id, "SecuritySettings","*")
    org_pwd_pol = security_settings.find('.//{http://soap.sforce.com/2006/04/metadata}passwordPolicies')
    if org_pwd_pol is None:
        raise SfpoldevchkError("Failed to retrieve Organization password policy")
    return org_pwd_pol

def get_profile_pwd_pols(metadata_url, session_id):
    """Get any Profile password policies."""
    list_metadata_response = call_list_metadata(metadata_url, session_id, 'profilePasswordPolicy', 'ProfilePasswordPolicy')
    if list_metadata_response is None:
        raise SfpoldevchkError("Failed to retrieve Profile password policies")
    return list_metadata_response.findall('.//{http://soap.sforce.com/2006/04/metadata}result')

def get_org_sess_settings(metadata_url, session_id):
    """Get the Organization session settings."""
    security_settings = call_read_metadata(metadata_url, session_id, "SecuritySettings","*")
    org_sess_settings = security_settings.find('.//{http://soap.sforce.com/2006/04/metadata}sessionSettings')
    if org_sess_settings is None:
        raise SfpoldevchkError("Failed to retrieve Organization session settings")
    return org_sess_settings

def get_profile_sess_settings(metadata_url, session_id):
    """Get any Profile session settings."""
    list_metadata_response = call_list_metadata(metadata_url, session_id, 'profileSessionSettings', 'ProfileSessionSetting')
    if list_metadata_response is None:
        raise SfpoldevchkError("Failed to retrieve Profile security settings")
    return list_metadata_response.findall('.//{http://soap.sforce.com/2006/04/metadata}result')

def tabulate(policy_deviations):
    """Print policy deviations in a table format.
    
    Arguments:
    policy_deviations -- an array with each item being itself an array of Profile name, setting description, Profile value, Organization value
    """
    # Add a header
    policy_deviations.insert(0,["PROFILE NAME", "SETTING", "PROFILE VALUE", "ORG VALUE"])
    # Need to get maximum value size for each column
    len_names, len_descs, len_profs, len_orgs = [], [], [], []
    for p in policy_deviations:
        len_names.append(len(p[0]))
        len_descs.append(len(p[1]))
        len_profs.append(len(p[2]))
        len_orgs.append(len(p[3]))
    name_max_size = max(len_names)
    desc_max_size = max(len_descs)
    prof_max_size = max(len_profs)
    org_max_size = max(len_orgs)
    # Complete the header
    policy_deviations.insert(1,["-"*name_max_size, "-"*desc_max_size, "-"*prof_max_size, "-"*org_max_size])    
    # Now print the table
    for p in policy_deviations:
        print("  " + p[0] + " "*(name_max_size - len(p[0])) + " | "
            + p[1] + " "*(desc_max_size - len(p[1])) + " | "
            + p[2] + " "*(prof_max_size - len(p[2])) + " | "
            + p[3] + " "*(org_max_size - len(p[3]))
            )

def main():
    """Salesforce policy deviation checker."""
    banner()
    if len(sys.argv) != 2 or sys.argv[1] in ['-h', '--help', '/h', '/?']:
        print("\nUsage is:\n  "+ sys.argv[0] + " <config_file>")
        print("Config file format:\n" + CONFIG_FILE_FORMAT)
        print("Account requires 'API Enabled' + 'View Setup and Configuration' + 'Modify Metadata Through Metadata API Functions'")
        exit(1)
    
    # Try to load config file
    try:
        hostname, username, password, token, debug = load_config(sys.argv[1])
    except Exception as e:
        error("Could not load config file", e, 1)
    
    # Establish REST API endpoint
    try:
        rest_api_url = 'https://' + hostname + '/services/data'
        check_api_ver_supported(rest_api_url)
        rest_api_url += '/v' + API_VERSION
    except Exception as e:
        error("Could not establish REST API endpoint", e, debug)
    
    try:
        session_id, metadata_url = login(hostname, username, password, token)
    except Exception as e:
        error("Could not login - check credentials and account permissions", e, debug)
    print("\nLogin successful")
    
    # Establish REST query API endpoint
    try:
        rest_query_api_uri = call_rest_api(rest_api_url, session_id)['query']
        rest_query_api_url = 'https://' + hostname + rest_query_api_uri
    except Exception as e:
        error("Could not establish REST query API endpoint", e, debug)
    
    # Get profile information
    try:
        profiles = get_profile_info(rest_query_api_url, session_id, metadata_url)
        print("- " + str(len(profiles)) + " profiles found")
    except Exception as e:
        error("Could not get profile information - check account permissions", e, debug)
    
    # Check for password policy deviation
    print("\nProfiles whose password policy is out of sync with the Org's (any deviation shown):")
    try:
        org_pwd_pol = get_org_pwd_pol(metadata_url, session_id)
        profile_pwd_pols = get_profile_pwd_pols(metadata_url, session_id)
    except Exception as e:
        error("Could not get password policy information", e, debug)
    # if profile_pwd_pols is not None, still technically possible for there to be no effective Profile password policies so we need to track
    profile_count = 0
    if profile_pwd_pols is not None:
        policy_deviations = []
        for p in profile_pwd_pols:
            try:
                policy_fullname = p.find('.//{http://soap.sforce.com/2006/04/metadata}fullName').text
                read_metadata_response = call_read_metadata(metadata_url, session_id, "ProfilePasswordPolicy", policy_fullname)
                profile_pwd_pol = read_metadata_response.find('.//{http://soap.sforce.com/2006/04/metadata}records')
                profile_fullname = profile_pwd_pol.find('.//{http://soap.sforce.com/2006/04/metadata}profile').text
            except Exception as e:
                exception = Exception(type(e).__name__, e.args, ElementTree.tostring(p))
                error("Error obtaining a particular profile's password policy", exception, debug)

            # The profile element can be empty - profile_pwd_pol orphaned? i.e. Profile deleted but not the associated Profile policy? Hence profile_count.
            if profile_fullname is None:
                continue
            profile_count += 1
            # Get the profile object from its Fullname so we can print the display name
            # Fullname in ProfilePasswordPolicy is lower case and Fullname in profiles is encoded
            try:
                profile = list(filter(lambda x: unquote(x['Fullname']).lower() == profile_fullname, profiles))[0]
            except:
                # Just use the Fullname
                profile = {'Name': profile_fullname}

            # Check each setting to see if Profile value different from Org value
            no_policy_deviation = True
            for p,o in PROFILE_TO_ORG_PWD_POL.items():
                try:
                    profile_value = profile_pwd_pol.find('.//{http://soap.sforce.com/2006/04/metadata}' + p).text
                    # Check if values need to be normalised for comparison
                    if len(o['values']) > 0:
                        equiv_org_value = o['values'][profile_value]
                    else:
                        equiv_org_value = profile_value
                    org_value = org_pwd_pol.find('.//{http://soap.sforce.com/2006/04/metadata}' + o["orgTerm"]).text
                    if equiv_org_value != org_value:
                        no_policy_deviation = False
                        policy_deviation = []
                        policy_deviation.append(profile['Name'])    # Profile name
                        policy_deviation.append(o['desc'])          # Setting description
                        policy_deviation.append(equiv_org_value)    # Profile value
                        policy_deviation.append(org_value)          # Org value
                        policy_deviations.append(policy_deviation)
                except Exception as e:
                    error("Error comparing profile password policy item " + p + " with Org value", e, debug)
            if no_policy_deviation:
                policy_deviations.append([profile['Name'], "", "", ""])
        tabulate(policy_deviations)
    if profile_count == 0:
        print("  <None>")
    else:
        print(str(profile_count) + " profiles found")
    
    # Check for session settings deviation
    print("\nProfiles whose session settings are out of sync with the Org's (any deviation shown):")
    try:
        org_sess_settings = get_org_sess_settings(metadata_url, session_id)
        profile_session_settings = get_profile_sess_settings(metadata_url, session_id)
    except Exception as e:
        error("Could not get session settings", e, debug)
    # if profile_session_settings is not None, still technically possible for there to be no effective Profile session settings so we need to track
    profile_count = 0
    if profile_session_settings is not None:
        policy_deviations = []
        for p in profile_session_settings:
            try:
                policy_fullname = p.find('.//{http://soap.sforce.com/2006/04/metadata}fullName').text
                read_metadata_response = call_read_metadata(metadata_url, session_id, "ProfileSessionSetting", policy_fullname)
                profile_session_setting = read_metadata_response.find('.//{http://soap.sforce.com/2006/04/metadata}records')
                profile_fullname = profile_session_setting.find('.//{http://soap.sforce.com/2006/04/metadata}profile').text
            except Exception as e:
                exception = Exception(type(e).__name__, e.args, ElementTree.tostring(p))
                error("Error obtaining a particular profile's session settings", exception, debug)
            
            # The profile element can be empty - profile_session_setting orphaned? i.e. Profile deleted but not the associated Profile policy? Hence profile_count.
            if profile_fullname is None:
                continue
            profile_count += 1
            # Get the profile object from its Fullname so we can print the display name
            # Fullname in ProfileSessionSetting is lower case and Fullname in profiles is encoded
            try:
                profile = list(filter(lambda x: unquote(x['Fullname']).lower() == profile_fullname, profiles))[0]
            except:
                # Just use the Fullname
                profile = {'Name': profile_fullname}
            
            # Check each setting to see if Profile value different from Org value
            no_policy_deviation = True
            for p,o in PROFILE_TO_ORG_SESS_SETTINGS.items():
                try:
                    profile_value = profile_session_setting.find('.//{http://soap.sforce.com/2006/04/metadata}' + p).text
                    # Check if values need to be normalised for comparison
                    if len(o['values']) > 0:
                        equiv_org_value = o['values'][profile_value]
                    else:
                        equiv_org_value = profile_value
                    org_value = org_sess_settings.find('.//{http://soap.sforce.com/2006/04/metadata}' + o["orgTerm"]).text
                    if equiv_org_value != org_value:
                        no_policy_deviation = False
                        policy_deviation = []
                        policy_deviation.append(profile['Name'])    # Profile name
                        policy_deviation.append(o['desc'])          # Setting description
                        policy_deviation.append(equiv_org_value)    # Profile value
                        policy_deviation.append(org_value)          # Org value
                        policy_deviations.append(policy_deviation)
                except Exception as e:
                    error("Error comparing profile session setting " + p + " with Org value", e, debug)
            if no_policy_deviation:
                policy_deviations.append([profile['Name'], "", "", ""])
        tabulate(policy_deviations)
    if profile_count == 0:
        print("  <None>")
    else:
        print(str(profile_count) + " profiles found")

############
### Main ###

if __name__ == "__main__":
    main()
