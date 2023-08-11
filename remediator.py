import base64
import copy
import logging
import os
import sys
import time
import requests
import uuid
import json
from xml.dom import minidom
from fishy_hspl_translator import getFishyHSPL
from rabbit_consumer_cr import RMQsubscriberCR
from rabbit_consumer_single import RMQSingleMessageSubscriber
from rabbit_producer import RMQproducer
import serviceGraph
import SecurityControlFunctions
import recipe_language
from datetime import datetime
from recipe_language import interpreter
import xml.etree.ElementTree as ET


logging.basicConfig(level=logging.DEBUG)
logging.getLogger("pika").setLevel(logging.CRITICAL)

#todo enable/disable
#API_ENDPOINT = "host.docker.internal"
API_ENDPOINT = "localhost"
ENV_API_ENDPOINT = os.environ.get("API_ENDPOINT")
if ENV_API_ENDPOINT is not None and isinstance(ENV_API_ENDPOINT, str):
    API_ENDPOINT = ENV_API_ENDPOINT

#todo
TMP_ADDR = None

class Remediator():

    def __init__(self, SecurityControlRepository=None, ThreatRepository=None, recipeToBeRun=None, GlobalScope=None) -> None:
        logging.info("Initializing security controls repository")
        if SecurityControlRepository is None:
            self.SecurityControlRepository = {}
        else:
            self.SecurityControlRepository = copy.deepcopy(SecurityControlRepository)

        logging.info("Initializing threat repository")
        if ThreatRepository is None:
            self.ThreatRepository = copy.deepcopy(ThreatRepository)
        else:
            self.ThreatRepository =  ThreatRepository

        logging.info("Initializing service graph")
        self.ServiceGraph = serviceGraph.ServiceGraph()

        logging.info("Initializing global scope")
        if GlobalScope is None:
            self.GlobalScope = {
                # "listTest1": [1, 2, 3],
                # "listTest2": ["a", "b", "c"],
                # "condizioneTest": False,
                # "varProva1": 10,
                # "varProva2": "prova",
                # "path_list": None,
                "rowCursor": 0,
                # "impacted_nodes": ["10.1.0.10", "10.1.0.11"], # integrity information, if any
                # "vulnerable_nodes": [],  # nodes vulnerable to the threat, if any
                # "services_involved": [],
            }

        logging.info("Initializing recipe repository")
        self.RecipeRepository = {
            "block_mac_address_recipe":{
                "description": "Block MAC address on a node",
                "requiredCapabilities": [""],
            },
            "block_malicious_user": {
                "description": "Block malicious user",
                "requiredCapabilities": [""],
            },
            "filter_payload_recipe": {
                "description": "Filter payload on impacted node",
                "requiredCapabilities": ["level_7_filtering"],
            },
            "filter_ip_port_recipe": {
                "description": "Filter ip and port on impacted node",
                "requiredCapabilities": ["level_4_filtering"],
            },
            "fishy_security_recipe": {
                "description": "Applies a fishy security policy to protect the impacted node",
                "requiredCapabilities": ["level_4_filtering"],
            },
            "redirect_domains_recipe": {
                "description": "Add rule to DNS server for redirection of malicious DNS domains queries to safe one",
                "requiredCapabilities": ["dns_policy_manager"],
            },
            "monitor_traffic_recipe": {
                "description": "Monitor traffic on impacted node",
                "requiredCapabilities": ["traffic_monitor"],
            },
            "put_into_reconfiguration_recipe": {
                "description": "Put impacted nodes into reconfiguration net",
                "requiredCapabilities": [],
            },
            "add_honeypot_recipe": {
                "description": "Add honeypot for each impacted node",
                "requiredCapabilities": [],
            },
            "shutdown_recipe": {
                "description": "Shutdown impacted nodes",
                "requiredCapabilities": [],
            },
            "isolate_recipe": {
                "description": "Isolate impacted nodes",
                "requiredCapabilities": [],
            },
            "fbm_recipe": {
                "description": "Call the fbm_function",
                "requiredCapabilities": [],
            },
        }

        self.CapabilityToSecurityControlMappings = {
            "level_4_filtering": "iptables",
            "level_7_filtering": "generic_level_7_filter",
            "level_4_monitor": "generic_network_traffic_monitor"
        }

        self.recipeToBeRun = recipeToBeRun

    def setCapabilitiesToSecurityControlMappings(self, requiredCapabilities: list):
        """Sets the CapabilityToSecurityControlMappings dictionary according to the capabilities needed for
        the execution of the selected recipe. Each capability is mapped to the respective security control
        that will be used to enforce that capability.
        Returns nothing"""

        for el in requiredCapabilities:
            for key, value in self.SecurityControlRepository.items():
                if el in value["capabilities"]:
                    self.CapabilityToSecurityControlMappings[el] = key
                    break


    def generateRule(self, capability, policy):
        """Generates a rule for policy enforcement in the language specific of that security control with
        which the policy will be enforced. It taps into the SecurityControlToFunctionMappings dictionary in
        which each SecurityControl is mapped to a command generator function.
        Returns a dictionary representing the rule.
        """
        ### DESIGN CONSIDERATION ###
        # This function works as a rule translator. The policy argument is actually called rule in the rest of
        # the Remediator class, and here gets translated to the specific format of the security control. Maybe in
        # the future would be better if elsewhere the rules are called Policies and become Rules
        # only after being translated from this function to the SecurityControl sepcific language.


        securityControlName = self.CapabilityToSecurityControlMappings[capability]
        ruleGenerator = SecurityControlFunctions.FunctionMappings[securityControlName] # this is a callable object, i.e. a function object

        if capability == "level_4_filtering":
            generatedRule = ruleGenerator(policy)
        else:
            generatedRule = ruleGenerator(policy)

        newRule = {"type": capability,
                    "enforcingSecurityControl": securityControlName,
                    "rule": generatedRule}

        return newRule

    def selectBestRecipe(self, threatName, threatLabel):
        """Selects the best recipe enforceable for the given threat taking into account the recipes priority. If
        a given recipe requires a capability not enforceable with any security control available in the
        SecurityControlsRepository it will return the next one in line that can be enforced.
        Returns the name of the selected recipe."""

        maxPriority = 0
        bestRecipeName = None
        for el in self.ThreatRepository[threatName][threatLabel]["recipes"]:
            if el["priority"] > maxPriority and self.checkEnforceability(el["recipeName"]):
                maxPriority = el["priority"]
                bestRecipeName = el["recipeName"]

        return bestRecipeName

    def checkEnforceability(self, recipeName):
        """Checks the enforceability of a given recipe, that is, for every required capability a SecurityControl
        capable of enforcing it is available in the SecuityControlRepository"""

        # Get the set of required capabilities from the RecipeRepository
        requiredCapabilities = set(self.RecipeRepository[recipeName]["requiredCapabilities"])

        # Get the set of enforceable capabilities from the SecurityControlRepository
        enforceableCapabilities = set()
        for el in self.SecurityControlRepository.values():
            enforceableCapabilities.update(el["capabilities"])

        if requiredCapabilities.issubset(enforceableCapabilities):
            return True
        else:
            return False

    def prepareDataForRemediationOfMalware(self, threatType, threatName, impacted_host_ip, attacker_port, attacker_ip):

        self.GlobalScope["threat_type"] = threatType  # malware
        self.GlobalScope["threat_name"] = threatName  # command_control / Cridex / Zeus
        self.GlobalScope["impacted_host_ip"] = impacted_host_ip  # 10.1.0.10
        self.GlobalScope["c2serversPort"] = attacker_port  # 22
        self.GlobalScope["attacker_ip"] = attacker_ip  # 12.12.12.12

        if threatName == "command_control":
            logging.info("Generic command and control threat detected, apply countermeasures ...")
            self.GlobalScope["rules_level_4"] = [
                {"level": 4, "victimIP": impacted_host_ip, "c2serversPort": attacker_port, "c2serversIP": attacker_ip, "proto": "TCP"}]

            suggestedRecipe = self.ThreatRepository[threatType][threatName]["suggestedRecipe"]
            print(
                f"Recommended recipe for the threat: \n{self.RecipeRepository[suggestedRecipe]['description']} with parameters: ")
            print(
                f"Impacted host ip: {impacted_host_ip} \nAttacker port: {attacker_port} \nAttacker ip: {attacker_ip}")
            self.suggested_recipe = suggestedRecipe
        elif threatName in self.ThreatRepository[threatType]:
            logging.info("Threat found in the repository, applying specific countermeasures ...")
            mitigation_rules = self.ThreatRepository[threatType][threatName]["rules"]
            self.GlobalScope["rules_level_7"] = [rule for rule in mitigation_rules if rule.get("level") == 7 and rule.get("proto") != "DNS"] # DNS rules are managed below
            self.GlobalScope["rules_level_4"] = [rule for rule in mitigation_rules if rule.get("level") == 4]

            # complete ThreatRepository data with fresh information regarding port and victim host received as alert
            for rule in self.GlobalScope["rules_level_4"]:
                rule["victimIP"] = impacted_host_ip
                rule["c2serversPort"] = attacker_port

            # add a blocking rule if the attacker ip present in the alert isn't already in the ThreatRepository
            threatRepositoryAttackers = [rule["c2serversIP"] for rule in mitigation_rules if rule.get("level") == 4]
            if attacker_ip not in threatRepositoryAttackers:
                self.GlobalScope["rules_level_4"].append({"level": 4, "victimIP": impacted_host_ip,
                                                    "c2serversPort": attacker_port,
                                                    "c2serversIP": attacker_ip,
                                                    "proto": "TCP"})

            # if the threat repository doesn't contain specific level_4_filtering rules
            # for this specific malware then generate them from the information gathered from the CLI
            if(len(self.GlobalScope["rules_level_4"]) == 0):
                self.GlobalScope["rules_level_4"] = [{"level": 4, "victimIP": impacted_host_ip,
                                                "c2serversPort": attacker_port,
                                                "c2serversIP": attacker_ip,
                                                "proto": "TCP"}]

            # get dns rules
            self.GlobalScope["domains"] = [rule["domain"] for rule in mitigation_rules if rule.get("proto") == "DNS"]

            # set impacted_nodes variable, that is used in the other recipes
            self.GlobalScope["impacted_nodes"] = [impacted_host_ip]

            # from here on is just logging
            suggestedRecipe = self.ThreatRepository[threatType][threatName]["suggestedRecipe"]
            print(
                f"Recommended recipe for the threat: ( {self.RecipeRepository[suggestedRecipe]['description']} )\nWith parameters: ")
            print(
                f"Impacted host ip: {impacted_host_ip} \nImpacted host port: {attacker_port} \nAttacker ip: {attacker_ip}")

            for rule in self.GlobalScope["rules_level_7"]:
                payload = rule["payload"]
                print(f"Payload: {payload}")
            self.suggested_recipe = suggestedRecipe
        else:
            logging.info("Threat not found in the repository, applying generic countermeasures ...")
            self.GlobalScope["impacted_nodes"] = [impacted_host_ip]
            suggestedRecipe = "isolate_recipe"
            print(
                f"Recommended recipe for the threat: \n{self.RecipeRepository[suggestedRecipe]['description']} with parameters: ")
            print(
                f"Impacted host ip: {impacted_host_ip} \nAttacker port: {attacker_port} \nAttacker ip: {attacker_ip}")

            self.suggested_recipe = suggestedRecipe

    def prepareDataForFishyRemediation(self, report):

        eventPayload = json.loads(report["extensions_list"])#.decode('utf-8'))
        self.GlobalScope["threat_type"] = "malware"  # malware
        self.GlobalScope["threat_name"] = report["event_name"] # command_control / Cridex / Zeus
        self.GlobalScope["impacted_host_ip"] = "10.1.0.10" #eventPayload["dst"]  # 10.1.0.10
        self.GlobalScope["c2serversPort"] = eventPayload["spt"]  # 22
        #todo
        global TMP_ADDR
        TMP_ADDR = eventPayload["src"]
        self.GlobalScope["attacker_ip"] = "12.12.12.12" # eventPayload["src"][:1] + "0" + eventPayload["src"][1:] # 12.12.12.12

        logging.info("Malware detected, apply countermeasures ...")

        self.GlobalScope["rules_level_4"] = [
            {"level": 4, "victimIP": self.GlobalScope['impacted_host_ip'], "c2serversPort": self.GlobalScope['c2serversPort'], "c2serversIP": self.GlobalScope['attacker_ip'], "proto": "TCP"}]

        suggestedRecipe = self.ThreatRepository[self.GlobalScope["threat_type"]][self.GlobalScope["threat_name"]]["suggestedRecipe"]

        print(
            f"Recommended recipe for the threat: \n{self.RecipeRepository[suggestedRecipe]['description']} with parameters: ")
        print(
            f"Impacted host ip: {self.GlobalScope['impacted_host_ip']} \nAttacker port: {self.GlobalScope['c2serversPort']} \nAttacker ip: {self.GlobalScope['attacker_ip']}")

        self.suggested_recipe = suggestedRecipe

    def cliInput(self):
        print(API_ENDPOINT)
        while 1:

            prompt = "Insert threat details with this format \n(threat type) (threat name) (impacted host ip) (attacker port) (attacker ip)\n>>> "
            inputData = input(prompt)
            if inputData == "q" or inputData == "Q":
                print("Terminating...")
                sys.exit()
            elif inputData == "":
                continue
            else:
                inputDataSplit = inputData.split()

            if (inputDataSplit[0] == "malware"):
                logging.info("Remediating malware ...")
                self.prepareDataForRemediationOfMalware(inputDataSplit[0],
                                    inputDataSplit[1],
                                    inputDataSplit[2],
                                    inputDataSplit[3],
                                    inputDataSplit[4])
            else:
                logging.info("Unsupported threat remediation ...")
                print("Only malware remediation is supported at the moment!")

            nameOfRecipeToBeRun = self.selectRecipeManually()

            self.remediateWithTextX(nameOfRecipeToBeRun)

    def remediateFishy(self, report):

        # inputDataSplit = input.split()

        # if (inputDataSplit[0] == "malware"):
        #     logging.info("Remediating malware ...")
        #     self.prepareDataForRemediationOfMalware(inputDataSplit[0],
        #                         inputDataSplit[1],
        #                         inputDataSplit[2],
        #                         inputDataSplit[3],
        #                         inputDataSplit[4])
        # else:
        #     logging.info("Unsupported threat remediation ...")
        #     print("Only malware remediation is supported at the moment!")

        self.prepareDataForFishyRemediation(report)

        routingKey = "edc_remediation_proposals"
        notification_producer_config = {'host': 'fishymq.xlab.si',
                                        'port': 45672,
                                        'exchange' : "edc_remediationsedcpoli_proposals",
                                        'login':'tubs',
                                        'password':'sbut'}

        init_rabbit_producer = RMQproducer(routingKey, notification_producer_config)
        correlation_id = str(uuid.uuid4())

        if report["pilot"] == "WBP":
            if report["event_name"] == "Malicious URL":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "filter_ip_port_recipe", "remediations": [
                    {"id": "filter_payload_recipe", "description": "Filter payload on impacted node", "details": "TO BE DEFINED"},
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "redirect_domains", "description": "Redirect DNS queries directed to malicious domains", "details": "TO BE DEFINED"},
                    ]}
            elif report["event_name"] == "Brute force":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "block_malicious_user", "remediations": [
                    {"id": "block_malicious_user", "description": "Block malicious user", "details": "TO BE DEFINED"},
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "put_into_reconfiguration_recipe", "description": "Put impacted nodes into reconfiguration net", "details": "TO BE DEFINED"},
                    ]}
            elif report["event_name"] == "Denial of service":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "filter_ip_port_recipe", "remediations": [
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "filter_payload_recipe", "description": "Filter payload on impacted node", "details": "TO BE DEFINED"},
                    {"id": "monitorr_traffic_recipe", "description": "Monitor traffic on impacted node", "details": "TO BE DEFINED"},
                    ]}
            elif report["event_name"] == "Unauthorized access to admin pages":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "block_mac_address_recipe", "remediations": [
                    {"id": "block_mac_address_recipe", "description": "Block MAC address", "details": "TO BE DEFINED"},
                    {"id": "filter_payload_recipe", "description": "Filter payload on impacted node", "details": "TO BE DEFINED"},
                    {"id": "monitorr_traffic_recipe", "description": "Monitor traffic on impacted node", "details": "TO BE DEFINED"},
                    ]}
        elif report["pilot"] == "F2F":
            if report["event_name"] == "WID attack":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "filter_ip_port_recipe", "remediations": [
                    {"id": "filter_payload_recipe", "description": "Filter payload on impacted node", "details": "TO BE DEFINED"},
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "redirect_domains", "description": "Redirect DNS queries directed to malicious domains", "details": "TO BE DEFINED"},
                    ]}
            elif report["event_name"] == "DID attack":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "filter_ip_port_recipe", "remediations": [
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "add_honeypot_recipe", "description": "Add honeypot for each impacted node", "details": "TO BE DEFINED"},
                    {"id": "put_into_reconfiguration_recipe", "description": "Put impacted nodes into reconfiguration net", "details": "TO BE DEFINED"},
                    ]}
            elif report["event_name"] == "DDoS attack":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "filter_ip_port_recipe", "remediations": [
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "add_honeypot_recipe", "description": "Add honeypot for each impacted node", "details": "TO BE DEFINED"},
                    {"id": "put_into_reconfiguration_recipe", "description": "Put impacted nodes into reconfiguration net", "details": "TO BE DEFINED"},
                    ]}
            elif report["event_name"] == "Brute force":
                gui_remediation_proposal_message = {"correlation_id": correlation_id, "type": "proposal", "recommended_remediation": "filter_ip_port_recipe", "remediations": [
                    {"id": "filter_ip_port_recipe", "description": "Filter ip and port on impacted node", "details": "TO BE DEFINED"},
                    {"id": "add_honeypot_recipe", "description": "Add honeypot for each impacted node", "details": "TO BE DEFINED"},
                    {"id": "put_into_reconfiguration_recipe", "description": "Put impacted nodes into reconfiguration net", "details": "TO BE DEFINED"},
                    ]}
        else:
            return

        for remediation in gui_remediation_proposal_message["remediations"]:
            remediation["details"] = json.dumps(json.loads(report["extensions_list"]), indent=4)

        init_rabbit_producer.send_message(gui_remediation_proposal_message)

        queueName = 'edc_remediation_selection'
        key = 'edc_remediation_selection'
        notification_consumer_config = {'host': 'fishymq.xlab.si',
                                        'port': 45672,
                                        'exchange' : 'edc_remediationsedcpoli_selection',
                                        'login':'tubs',
                                        'password':'sbut'}

        init_rabbit_consumer = RMQSingleMessageSubscriber(queueName, key, notification_consumer_config, correlation_id)
        init_rabbit_consumer.setup() # this is blocking
        received_message = init_rabbit_consumer.get_received_message()
        print("Received GUI selection:", received_message)

        # example response message
        # {"selected_remediation": "isolate_recipe", "correlation_id": "erferferf"}

        nameOfRecipeToBeRun = received_message["selected_remediation"]

        print(nameOfRecipeToBeRun)

        #todo enable/disable
        self.remediateWithTextX(nameOfRecipeToBeRun)

    def reportCLIInputAndGUIRemediationSelection(self):
        while 1:
            prompt = "Insert threat details with this format \n(threat type) (threat name) (impacted host ip) (attacker port) (attacker ip)\n>>> "
            inputData = input(prompt)
            if inputData == "q" or inputData == "Q":
                print("Terminating...")
                sys.exit()
            elif inputData == "":
                continue
            else:
                self.remediateFishy(inputData)

    def message_adapter(self, channel, method, properties, body):

        #print(" [x] Received %r" % body)
        message = json.loads(body.decode('utf-8'))

        if message["task_type"] != "reports.create.cef":
            print("Ignoring message of type: " + message["task_type"])
            return

        report = message["details"]

        print("Received threat report: ")
        print(report)

        self.remediateFishy(report)

    def consumerCR(self):

        queueName = 'reportsedc'
        key = "reports.create.cef" # reports.create.cef (Prod)  reportsedc (testing)
        notification_consumer_config = {'host': 'fishymq.xlab.si',
                                        'port': 45672,
                                        'exchange' : "tasks", # tasks (Prod) reportsedc (testing)
                                        'login':'tubs',
                                        'password':'sbut'}

        # example message
        # {"payload": "malware Zeus 10.1.0.10 22 12.12.12.12"}
        init_rabbit = RMQsubscriberCR(queueName, key, notification_consumer_config, self.message_adapter)
        init_rabbit.setup()

    def fileInput(self):

        if(len(sys.argv) < 2):
            # In case no input filename is given exit
            # print("No input file given, terminating...")
            # sys.exit()
            fileName = "alert.json"
        else:
            # In case no input filename is given use by default alert.json
            fileName = sys.argv[1]

        with open(fileName, "r", encoding='utf8') as alertFile:
            alert = json.load(alertFile)
            print(alert)

            self.ServiceGraph.plot()

            # alert of type malware
            #todo check ip flow direction
            self.prepareDataForRemediationOfMalware(alert["Threat_Name"],  # malware
                                alert["Threat_Label"],  # command_control / Cridex / Zeus
                                alert["Threat_Finding"]["Source_Address"], # alert["Threat_Finding"]["Source_Address"],
                                alert["Threat_Finding"]["Destination_Port"], # alert["Threat_Finding"]["Destination_Port"],  # 22
                                alert["Threat_Finding"]["Destination_Address"]) # alert["Threat_Finding"]["Destination_Address"]) # 54.154.132.12

            bestRecipeName = self.selectBestRecipe(alert["Threat_Name"], alert["Threat_Label"])
            self.recipeToBeRun = self.RecipeRepository[bestRecipeName]["value"]
            self.setCapabilitiesToSecurityControlMappings(self.RecipeRepository[bestRecipeName]["requiredCapabilities"])

            self.remediateWithTextX(bestRecipeName)

    def remediateWithTextX(self, nameOfRecipeToBeRun):

        if nameOfRecipeToBeRun is None:
            raise Exception("Recipe has not been set")

        self.interpetWithTextX(recipeName=f"recipes/{nameOfRecipeToBeRun}.rec")

        # values: List = timeit.repeat(stmt=self.getSTIXReport, repeat=100, number=1)
        # values.pop(0)
        # print(f"min: {min(values)}, max: {max(values)}")
        # for value in values:
        #     print(str(value).replace(".", ","))

        #self.getSTIXReport()

        #self.getCACAORemediationPlaybook()

    def selectRecipeManually(self):
        """Manually select which recipe to apply, according to the list shown in the terminal.
        Returns the string of the selected recipe."""

        while (True):
            print(
                "1) Filter payload on impacted node\n"
                "2) Filter ip and port on impacted node\n"
                "3) Monitor traffic on impacted node\n"
                "4) Put impacted nodes into reconfiguration net\n"
                "5) Redirect DNS queries directed to malicious domains\n"
                "6) Add honeypot for each impacted node\n"
                "7) Shutdown impacted nodes\n"
                "8) Isolate impacted nodes\n"
                "9) Apply fishy security policy\n"
                "Q) Quit"
                ""
            )

            choice = input("Select the recipe to apply: \n>>> ")
            if choice == "q" or choice == "Q":
                print("Terminating...")
                sys.exit()
            elif int(choice) == 1:
                return "filter_payload_recipe"
                # with open("./interpreterTest2.txt", "r", encoding='utf8') as file:
                #     content = file.read()
            elif int(choice) == 2:
                return "filter_ip_port_recipe"
            elif int(choice) == 3:
                return "monitor_traffic_recipe"
            elif int(choice) == 4:
                return "put_into_reconfiguration_recipe"
            elif int(choice) == 5:
                return "redirect_domains_recipe"
            elif int(choice) == 6:
                return "add_honeypot_recipe"
            elif int(choice) == 7:
                return "shutdown_recipe"
            elif int(choice) == 8:
                return "isolate_recipe"
            elif int(choice) == 9:
                return "fishy_security_recipe"
            else:
                print("Invalid input")

    def interpetWithTextX(self, recipeName):
        # This is the TextX interpreter.

        # Shows starting state of the landscape
        self.ServiceGraph.plot()

        interpreter = recipe_language.interpreter.Interpreter(globalScope=self.GlobalScope, recipeFile=recipeName, remediator=self)
        interpreter.launch()

        logging.info("Starting interpreter ...")

    def lowerCaseXMLTags(self, xml_string):

        # parse the xml string
        dom = minidom.parseString(xml_string)

        # iterate through all elements in the xml
        for node in dom.getElementsByTagName("*"):
            # change the first letter of the tag name to lowercase
            node.tagName = node.tagName[0].lower() + node.tagName[1:]

        # return the modified xml as a string
        return dom.toxml()

    def refinePolicy(self, policy):
        """ Refines a policy by first creating a new HSPL configuration file and then calling the Refinement engine
            to which the HSPL is passed. The Refinement engine will return a new Intermediate Policy that will be
            passed to the Security Capability translator to generate the low level rule. In the end the low level
            rule will be added to the service graph.
            Returns the low level rules as a list of lists.
        """

        # Example policy:
        # {'level': 4, 'proto': 'TCP', 'c2serversIP': '2.3.4.5', 'victimIP': '10.1.0.10', 'c2serversPort': '22'}

        hspl_xml_tree = getFishyHSPL("ip_address", policy["c2serversIP"], "is not authorized to access", "Subnet1.1")

        ### Load HSPL on Central Repository ###

        # Get the current UTC time
        now_utc = datetime.utcnow()
        # Format the time as a string in ISO 8601 format with milliseconds and a 'Z' suffix
        time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        url="https://" + "fishy.xlab.si/tar/api/policies"

        headers = {'Content-Type': 'application/json'}

        # Serialize the XML tree to a string
        xml_string = ET.tostring(hspl_xml_tree.getroot(), encoding='utf-8', method='xml')

        # # Convert the serialized string to bytes
        # xml_bytes = xml_string.encode('utf-8')

        # Encode the bytes to base64
        encoded_string = base64.b64encode(xml_string).decode('utf-8')

        data = {"payload":encoded_string,"mode":"standalone"}

        message = {"source":"edc-rem","HSPL":json.dumps(data),"status":"both","timestamp":time_str}
        print(message)

        raw_response = requests.post(url, headers=headers, data=json.dumps(message))
        response = json.loads(raw_response.text)
        policy_id_cr = response["id"]

        if raw_response.status_code == 201:
            response_data = raw_response.json()
            print("HSPL loaded on CR!")
            print(response_data)
        else:
            print("Error:", raw_response.status_code)

        #######################################

        low_level_rules = self.refineHSPL(policy_id_cr)

        print("Low level rules: ")
        print(low_level_rules)

        # Example return value
        # [['iptables -j DROP  -d 10.1.1.0/24 -s 12.12.12.12 -m conntrack --ctstate NEW,ESTABLISHED -A FORWARD ', 'iptables -j DROP  -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -d 12.12.12.12 -s 10.1.1.0/24 ']]

        return low_level_rules

    def getLowLevelRule(self, filename, mspl_id_cr):

        # call security capability translator, that will return in output a low level rule

        files = {"file":open(filename,"rb")}
        r = requests.post(f"http://{API_ENDPOINT}:6000/translator", files=files, data={"upload":"Upload"})

        output = None
        if("File uploaded correctly" in r.text):
            r = requests.post(f"http://{API_ENDPOINT}:6000/translator", data={"translate":"Translate", "destnsf":""})
            if not("html" in r.text):
                output = r.text
            else:
                start_idx = r.text.index("<h3>")
                end_idx = r.text.index("</h3>")
                output = r.text[start_idx+4:end_idx]

            result = output.splitlines()


            # todo remove the code below, and just return low_level_rules.
            ###############
            new_list = []

            global TMP_ADDR
            print("TMP_ADDR: " + TMP_ADDR)
            for el in result:
                # Replace the old_ip with new_ip using the replace() method
                modified_string = el.replace("12.12.12.12", TMP_ADDR)
                # Append the modified string to the new list
                new_list.append(modified_string)

            result = new_list

            ###############

            ### Load Configuration on Central Repository ###

            # Get the current UTC time
            now_utc = datetime.utcnow()
            # Format the time as a string in ISO 8601 format with milliseconds and a 'Z' suffix
            time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

            url="https://" + "fishy.xlab.si/tar/api/configurations"

            headers = {'Content-Type': 'application/json'}

            data = {"payload":result,"mode":"standalone"}

            message = {"source":"edc-rem","data":json.dumps(data),"status":"both","timestamp":time_str,"mspl_id":mspl_id_cr}

            raw_response = requests.post(url, headers=headers, data=json.dumps(message))
            response = json.loads(raw_response.text)

            if raw_response.status_code == 201:
                response_data = raw_response.json()
                print("Configuration loaded on CR!")
                print(response_data)
            else:
                print("Error:", raw_response.status_code)

            ################################################

            return result

    def refineHSPL(self, policy_id_cr):
        """ Refines the HSPL stored in the fishy_hspl.xml file by sending it to the refinement
            engine API, which produces an intermediate policy representation that is saved in
            files called refinement_output(index).xml"""

        hspl_filename = "fishy_hspl.xml"
        cookies = {"policy_filename": hspl_filename}

        #Upload HSPL

        url = f"http://{API_ENDPOINT}:5000/upload_hspl"
        file = {"file": open(hspl_filename, "rb")}
        response = requests.post(url, files=file)
        #print(response.text)

        # Get NSFs configurations

        url = f"http://{API_ENDPOINT}:5000/refinement_no_gui"
        response = requests.get(url, cookies=cookies)
        #print(response.text)

        # Execute refinement

        url = f"http://{API_ENDPOINT}:5000/refinement_no_gui"
        data = {"hspl1": ["firewall-1"]} # what about {"hspl1": ["firewall-HP", "firewall-1"]}?
        response = requests.post(url, cookies=cookies, json=data)
        #print(response.text)
        # Response example:
        # {"fishy_hspl_1666080055":["firewall-HP_IpTables_RuleInstance.xml","firewall-1_IpTables_RuleInstance.xml"]}

        url = f"http://{API_ENDPOINT}:5000/result"
        nsf_confs = json.loads(response.text)
        index = 1

        low_level_rules = []
        for key, value in nsf_confs.items():
            for nsf_conf in value:

                request_url = f"{url}/{key}/{nsf_conf}"
                #print(request_url)
                response = requests.get(request_url)

                # The XML file received must pass through the lowerCaseXMLTags function because
                # the security capability model doesn't recognize XML tags if the first
                # letter is uppercase. The refinement engine produces XML policies
                # in which the first letter is upper case, hence this step is needed.
                xml_string = self.lowerCaseXMLTags(response.text)
                xml = minidom.parseString(xml_string)
                prettyxml_string = xml.toprettyxml() # this is the MSPL
                # print(prettyxml)

                ### Load MSPL on Central Repository ###

                # Get the current UTC time
                now_utc = datetime.utcnow()
                # Format the time as a string in ISO 8601 format with milliseconds and a 'Z' suffix
                time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

                url="https://" + "fishy.xlab.si/tar/api/mspl"

                headers = {'Content-Type': 'application/json'}

                # Encode the bytes to base64
                base64_mlsp_string = base64.b64encode(prettyxml_string.encode('utf-8')).decode('utf-8')

                data = {"payload":base64_mlsp_string,"mode":"standalone"}

                message = {"source":"edc-rem","data":json.dumps(data),"status":"both","timestamp":time_str,"policy_id":policy_id_cr}

                raw_response = requests.post(url, headers=headers, data=json.dumps(message))
                response = json.loads(raw_response.text)
                mspl_id_cr = response["id"]

                if raw_response.status_code == 201:
                    response_data = raw_response.json()
                    print("MSPL loaded on CR!")
                    print(response_data)
                else:
                    print("Error:", raw_response.status_code)

                #######################################

                with open(f"refinement_output{index}.xml", 'w') as file:
                    file.write(prettyxml_string)

                configuration = self.getLowLevelRule(f"refinement_output{index}.xml", mspl_id_cr)
                low_level_rules.append(configuration)

                index += 1

        return low_level_rules

    def initializeSecurityCapabilityModel(self):

        files = {'file':open('./definitivo.xmi','rb')}
        r = requests.post(f'http://{API_ENDPOINT}:6000/converter', files=files, data={'upload':'Upload'})

        if('File uploaded correctly' in r.text):
            r = requests.post(f'http://{API_ENDPOINT}:6000/converter', data={'generate':'Generate'})
            if('xsd' in r.text.lower()):
                print('Capability Data Model generated correctly.')

        nsf_to_generate = "iptables"

        files = {'file':open('./NSFCatalogue.xml','rb')}
        r = requests.post(f'http://{API_ENDPOINT}:6000/langGen', files=files, data={'upload':'Upload'})

        if('File uploaded correctly' in r.text):
            if(nsf_to_generate is not None):
                r = requests.post(f'http://{API_ENDPOINT}:6000/langGen', data={'generate':'Generate', 'nsf':nsf_to_generate})
                start_idx = r.text.index('<h3>')
                end_idx = r.text.index('</h3>')
                output = r.text[start_idx+4:end_idx]
            else:
                r = requests.post(f'http://{API_ENDPOINT}:6000/langGen', data={'generateAll':'GenerateAll'})
                if(r.text.count('generated')>=6):
                    output = 'All NSF Languages have been generated correctly.'

            print(output)

def main():

    ####################### CLI input examples ########################
    # malware command_control 10.1.0.10 22 12.12.12.12                #
    # malware Cridex 10.1.0.10 22 12.12.12.12                         #
    # malware Zeus 10.1.0.10 22 12.12.12.12                           #
    # malware Neptune 10.1.0.10 22 12.12.12.12                        #
    ###################################################################

    with open("SecurityControlRepository.json", "r", encoding='utf8') as SecurityControlRepositoryFile:
        securityControlRepository = json.load(SecurityControlRepositoryFile)["SecurityControls"]
    with open("ThreatRepository.json", "r", encoding='utf8') as ThreatRepositoryFile:
        threatRepository = json.load(ThreatRepositoryFile)["Threats"]

    remediator = Remediator(SecurityControlRepository=securityControlRepository,
                            ThreatRepository=threatRepository)

    #remediator.fileInput()
    #remediator.initializeSecurityCapabilityModel()
    #remediator.cliInput()
    #remediator.reportCLIInputAndGUIRemediationSelection()
    remediator.consumerCR()

if __name__ == "__main__":

    #refineHSPL()
    main()