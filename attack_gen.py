import xml.etree.ElementTree as ET

def process_nessus_file(nessus_file_path, output_file_path):
    # Load and parse the .nessus file
    nessus_tree = ET.parse(nessus_file_path)
    root = nessus_tree.getroot()

    refined_hacl_rules = []
    vul_properties = []
    vul_exists = []
    network_service_info = []
    hosts = []

    # Iterate through each host in the file
    for host in root.findall('.//ReportHost'):
        hostname = host.attrib['name']
        hosts.append(hostname)

        # Iterate through each report item within the host
        for item in host.findall('.//ReportItem'):
            port = item.attrib.get('port', '0')
            protocol = item.attrib.get('protocol', 'N/A')
            svc_name = item.attrib.get('svc_name', 'N/A')

            # Ignore entries where port is 0
            if port != '0':
                # Create HACL rule for each valid item
                hacl_rule = f"hacl(internet, '{hostname}', '{protocol}', '{port}')."
                refined_hacl_rules.append(hacl_rule)

                # Gather vulnerability and service information
                cve_list = [cve.text for cve in item.findall('.//cve')]
                for cve in cve_list:
                    vul_exists.append(f"vulExists('{hostname}', '{cve}', '{svc_name}').")
                    vul_properties.append(f"vulProperty('{cve}', remoteExploit, privEscalation).")
                if cve_list:  # Only add network service info if there's at least one CVE
                    network_service_info.append(f"networkServiceInfo('{hostname}', '{svc_name}', '{protocol}', '{port}', '{svc_name}').")

    # Prepare the content for the output file
    attack_p_content = "attackerLocated(internet).\n"
    # Add attack goals for each host
    for host in hosts:
        attack_p_content += f"attackGoal(execCode('{host}',_)).\n"
    attack_p_content += "\n"
    attack_p_content += "\n".join(sorted(set(refined_hacl_rules))) + "\n"
    attack_p_content += "\n".join(sorted(set(vul_exists))) + "\n"
    attack_p_content += "\n".join(sorted(set(vul_properties))) + "\n"
    attack_p_content += "\n".join(sorted(set(network_service_info))) + "\n"

    # Write the content to the output file
    with open(output_file_path, "w") as file:
        file.write(attack_p_content)

# Example usage:
process_nessus_file("./data/vul_bivxy9.nessus", "./data/nattack.P")
