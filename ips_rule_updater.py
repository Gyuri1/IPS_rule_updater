#
# FMC IPS rule updater
# 

# import required dependencies
import json
import argparse
import urllib3
from urllib.parse import quote

# FMC Credential file
import fmc_config

# FMC Class
from fmc_class import fmc

# disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def ips_rule_updater(ips_policy, ips_rulefilter, rule_action, verbose):
    """
    This function will update the IPS rule action based on the filter
    :param ips_policy:
    :param ips_rulefilter:
    :param rule_action:
    :param verbose:
    :return:
    """




    # read the parameters
    ips_policy_id = ""

    if verbose:
        print("Get FMC token:")

    # Set variables for execution.

    device = fmc_config.host
    username = fmc_config.admin
    password = fmc_config.password
    target_domain = fmc_config.target_domain

    # Initialize a new api object
    if verbose:
        print("FMC authentication for this FMC:", device)

    api = fmc(host=device, username=username, password=password)
    api.tokenGeneration(target_domain)

    if verbose:
        print("Token received.")
        print("Authorized domains:")
        for domain in api.domains["domains"]:
            print("Domain name:", domain["name"], "UUID:", domain["uuid"])

    if verbose:
        print("Reading IPS policy ID:")
    result = api.get_ips_policies()
    # json_formatted_str = json.dumps(result, indent=2)

    ips_policies = result["items"]
    for i in ips_policies:
        if (i["name"] == ips_policy) and (i["type"] == "intrusionpolicy"):
            ips_policy_id = i["id"]

    if verbose:
        print("Intrusionpolicy name:", ips_policy, "ips_policy_id:", ips_policy_id)

    coded_filter = quote(ips_rulefilter)
    if verbose:
        print("Reading IPS rules based on filter:", ips_rulefilter)
        print("Coded filter:", coded_filter)

    result = api.get_ips_rules_filtered(ips_policy_id, coded_filter)

    # json_formatted_str = json.dumps(result, indent=2)
    all_data=[]
    if "items" in result:
        ips_rules = result["items"]
        for i in ips_rules:
            if verbose:
                print("name:", i["name"], "id:", i["id"], "type:", i["type"], )
            # print IPS rule content
            data = api.get_ips_rule(str(i["id"]))
            json_formatted_str = json.dumps(data, indent=2)
            if verbose:
                print(json_formatted_str)

            """ 
          #update the rule
          data='{  "ruleAction": {  "defaultState": "'+rule_action+'"} }'
          """
            # MINIMUM VALUE
            """
          {
          "type": "IntrusionRule",
          "id": "f2b1d0f6-9263-5c32-a6e0-31deaf4cc213", 
          "ruleAction": [
              
              {
                "defaultState": "ALERT",
                "policy": {
                  "name": "TEST1",
                  "id": "005056AE-FC0E-0ed3-0000-261993170149",
                  "type": "IntrusionPolicy",
                  "isSystemDefined": false
                }
              }
            ]
          }       
          """

            # Iterate over each item in the 'ruleAction' list
            for item in data['ruleAction']:
                # Check if the 'name' of the 'policy' is matching to the 'ips_policy' variable
                if item['policy']['name'] == ips_policy:
                    # If it is, change the 'defaultState' to "ALERT"
                    item['overrideState'] = rule_action
                    all_data.append(data)


        if verbose:
            print("Updating the Rule with all_data: ", all_data)
        #json_formatted_str = json.dumps(api.put_ips_rule(str(i["id"]), data), indent=2)
        json_formatted_str = json.dumps(api.put_ips_rule_bulk( data=all_data), indent=2)
        if verbose:
            print(json_formatted_str)


# Stand Alone execution
if __name__ == "__main__":
    # read the parameters
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False,
                                     description="""FMC IPS Snort3 Rule Action Updater 
     Example: ips_rule_updater.py -p ips_policy_name -f 'ips filter' -a action -v """
                                     )
    parser.add_argument("-p", help="FMC IPS policy name", required=True)
    parser.add_argument("-f", help="FMC IPS filter", required=True)
    parser.add_argument("-a", help="Snort 3 rule action (DROP/ALERT/DISABLE)", required=True)
    parser.add_argument("-v", help="Eanble verbose mode", action='store_true')
    args = parser.parse_args()

    ips_policy = args.p
    ips_policy = ips_policy.strip()

    ips_rulefilter = args.f
    ips_rulefilter = ips_rulefilter.replace("'", "")
    ips_rulefilter = ips_rulefilter.strip()

    rule_action = args.a
    rule_action = rule_action.strip()

    if args.v:
        print("IPS rule filter:", ips_rulefilter)
        print("Rule action:", rule_action)
    ips_rule_updater(ips_policy=ips_policy, ips_rulefilter=ips_rulefilter, rule_action=rule_action, verbose=args.v)
