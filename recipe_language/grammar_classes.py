from dataclasses import dataclass
import logging
from typing import Dict, Optional
from remediator import Remediator
import EnvironmentFunctions
from .support_functions import getVarFromContext

logging.basicConfig(level=logging.DEBUG)

#### Helper classes ####

# these, together with the hierarchical ones, are NOT grammar rules, that is, are not meant to be used
# as classes for their respective grammar rules. So are not used to generate the Model, a.k.a the AST
# of the Recipe, in fact they are neither passed to textx for the Meta-model generation. Instead
# they are just used for passing base functionalities to the Grammar rules' classes, such as logging
# or, for the hierarchical ones, for having a base class for every child rule, such as with
# Statement -> commands.

class LogClass:
    """Base class with logging capabilities"""

    def info(self):
        print(f"+{self.__class__.__name__}+")

#### Hierarchical classes ####

#  only needed for strict typing of grammar rules' class attributes

class Statement(LogClass):
    def run(self, *args):
        pass
    def testRun(self, *args):
        pass

class FunctionCall(Statement):
    pass

############################################################################################################################
## ATTENTION: When adding a new grammar rule remember to add its class to the recipe_classes list at the end of this file ##
############################################################################################################################

#### Grammar classes ####

@dataclass
class VarReferenceOrString:
    """Grammar rule defining a wrapper for variables and string raw values in the Recipe language"""

    parent: object
    value: object

    def getValue(self, scope):
        if isinstance(self.value, VarReference):
            return self.value.getValue(scope)
        else:
            return self.value

@dataclass
class VarReference:
    """Grammar rule defining variables in the Recipe language"""

    parent: object
    value: str

    def getValue(self, scope):
        return getVarFromContext(self.value, scope)

@dataclass
class Recipe(LogClass):
    """Grammar rule for the Recipe root object, containing a list of Statements"""

    statements: list[Statement]

    def run(self, scope, remediator):

        for el in self.statements:
            el.run(scope, remediator)

    def testRun(self, scope):
        super().info()
        print("Running the recipe")

        for el in self.statements:
            el.testRun(scope)

        print(f"Recipe end")

@dataclass
class Iteration(Statement):
    """ Grammar rule for the "execute" Recipe language command
        Sample expression: execute 'simpleFunction'
    """

    parent: object
    iterationExpression: VarReference
    statements: list[Statement]

    def run(self, scope, remediator):

        iterateScope = { "outerScope": scope }

        # for debug only, it's not a functional part
        iteration_list=self.iterationExpression.getValue(scope)
        print(f"Iteration list: {iteration_list}")

        for item in self.iterationExpression.getValue(scope):
            iterateScope["iteration_element"] = item
            for el in self.statements:
                el.run(iterateScope, remediator)

        print(f"End iteration")

    def testRun(self, scope):
        super().info()

        iterateScope = { "outerScope": scope }
        print(f"Iterating on: {self.iterationExpression.getValue(scope)}")

        for item in self.iterationExpression.getValue(scope):
            iterateScope["iteration_element"] = item
            for el in self.statements:
                el.testRun(iterateScope)

        print(f"End iteration")

@dataclass
class Condition(Statement):
    """ Grammar rule for the "execute" Recipe language command
        Sample expression: execute 'simpleFunction'
    """

    parent: object
    notClause: bool
    conditionExpression: VarReferenceOrString
    ifStatements: list[Statement]
    elseStatements: list[Statement]


    def run(self, scope, remediator):
        conditionScope = { "outerScope": scope }

        if self.conditionExpression.getValue(scope) is not self.notClause:

            for el in self.ifStatements:
                el.run(conditionScope, remediator)

        elif len(self.elseStatements) > 0:

            for el in self.elseStatements:
                el.run(conditionScope, remediator)

    def testRun(self, scope):
        super().info()

        conditionScope = { "outerScope": scope }

        print(f"Not clause: {self.notClause}")
        print(f"Condition expression: {self.conditionExpression.getValue(scope)}")

        print("If block")

        for el in self.ifStatements:
            el.testRun(conditionScope)

        print(f"End if block")

        if len(self.elseStatements) > 0:
            print("Else block")

            for el in self.elseStatements:
                el.testRun(conditionScope)

            print(f"End else block")

@dataclass
class ListPaths(FunctionCall):
    """ Grammar rule for the "list_paths" Recipe language command
        Sample expression: list_paths from impacted_host to 'attacker'
    """

    parent: object
    sourceExpression: VarReferenceOrString
    destinationExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        source = self.sourceExpression.getValue(scope)
        destination = self.destinationExpression.getValue(scope)
        logging.info("list_paths from " + f"{source}" + " to " + f"{destination}")

        try:
            scope["path_list"] = remediator.ServiceGraph.list_paths(source, destination)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Source: {self.sourceExpression.getValue(scope)}, "
                f"Destination: {self.destinationExpression.getValue(scope)}")

@dataclass
class FindNode(FunctionCall):
    """ Grammar rule for the "find_node" Recipe language command
        Sample expression: find_node of type 'firewall' in network_path with 'level_4_filtering'
    """

    parent: object
    nodeTypeExpression: VarReferenceOrString
    networkPathExpression: VarReferenceOrString
    nodeCapabilityExpression: Optional[VarReferenceOrString] # from Python 3.10 also VarReferenceOrString | None

    def run(self, scope, remediator: Remediator):

        nodeType = self.nodeTypeExpression.getValue(scope)
        networkPath = self.networkPathExpression.getValue(scope)

        # for now supporting only one capability maximum in input
        if self.nodeCapabilityExpression is not None:
            nodeCapability = self.nodeCapabilityExpression.getValue(scope)
            nodeCapabilities = [nodeCapability]
            logging.info("find_node of type " + f"{nodeType}" + " in " + f"{networkPath}" +
                            " with " + f"{nodeCapability}")
        else:
            nodeCapabilities = []
            logging.info("find_node of type " + f"{nodeType}" + " in " + f"{networkPath}")

        try:
            found_node = remediator.ServiceGraph.find_node_in_path(networkPath, nodeType, nodeCapabilities)
        except Exception as ex:
            raise ex  # just rethrow it for now

        if found_node != "Not found":
            scope["found_node"] = found_node
            scope["found"] = True
        else:
            scope["found_node"] = None
            scope["found"] = False

    def testRun(self, scope):
        super().info()
        print(f"Node type: {self.nodeTypeExpression.getValue(scope)}, "
                f"Path: {self.networkPathExpression.getValue(scope)}, "
                f"""Node capability: {'capability not present' if self.nodeCapabilityExpression is
                                        None else self.nodeCapabilityExpression.getValue(scope)}""")

@dataclass
class AddFirewall(FunctionCall):
    """ Grammar rule for the "add_firewall" Recipe language command
        Sample expression: add_firewall behind impacted_host in network_path with 'level_4_filtering'
    """

    parent: object
    impactedNodeExpression: VarReferenceOrString
    networkPathExpression: VarReferenceOrString
    filteringCapabilitiesExpression: Optional[VarReferenceOrString] # from Python 3.10 also VarReferenceOrString | None

    def run(self, scope, remediator: Remediator):

        impactedNode = self.impactedNodeExpression.getValue(scope)
        networkPath = self.networkPathExpression.getValue(scope)

        # for now supporting only one capability maximum in input
        if self.filteringCapabilitiesExpression is not None:
            filteringCapability = self.filteringCapabilitiesExpression.getValue(scope)
            filteringCapabilities = [filteringCapability]
            logging.info("add_firewall behind " + f"{impactedNode}" + " in " + f"{networkPath}" + " with " +
                            f"{filteringCapability}")
        else:
            # by default assign level 4 and 7 capabilities if not specified otherwise
            filteringCapabilities = ["level_4_filtering", "level_7_filtering"]
            logging.info("add_firewall behind " + f"{impactedNode}" + " in " + f"{networkPath}")

        try:
            new_node = remediator.ServiceGraph.add_firewall(impactedNode, networkPath, filteringCapabilities)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        if self.filteringCapabilitiesExpression is not None:
            print(f"Impacted node with ip: {self.impactedNodeExpression.getValue(scope)}, "
                    f"Firewall positioning: {self.networkPathExpression.getValue(scope)}, "
                    f"Filtering type: {self.filteringCapabilitiesExpression.getValue(scope)}")
        else:
            print(f"Impacted node with ip: {self.impactedNodeExpression.getValue(scope)}, "
                    f"Firewall positioning: {self.networkPathExpression.getValue(scope)}")

@dataclass
class AddFilteringRules(FunctionCall):
    """ Grammar rule for the "add_filtering_rules" Recipe language command
        Sample expression: add_filtering_rules rules_level_4 to new_node
    """

    parent: object
    filteringRulesExpression: VarReference
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        filteringRules: Dict = self.filteringRulesExpression.getValue(scope)
        node = self.nodeExpression.getValue(scope)
        logging.info("add_filtering_rules " + "rules" + " to " + f"{node}")

        try:
            translatedRules = []
            for rule in filteringRules:
                if rule["level"] == 4:
                    translatedRules.append(remediator.generateRule("level_4_filtering", rule))
                else:
                    translatedRules.append(remediator.generateRule("level_7_filtering", rule))
            remediator.ServiceGraph.add_filtering_rules(node, translatedRules)
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Level 7 rules reference: {self.filteringRulesExpression.getValue(scope)}, "
                f"Node: {self.nodeExpression.getValue(scope)}")

@dataclass
class EnforceSecurityPolicies(FunctionCall):
    """ Grammar rule for the "enforce_security_policies" Recipe language command
        Sample expression: enforce_security_policies policies to new_node
    """

    parent: object
    securityPoliciesExpression: VarReference
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        securityPolicies: Dict = self.securityPoliciesExpression.getValue(scope)
        node = self.nodeExpression.getValue(scope)
        logging.info("enforce_security_policies " + "policies" + " to " + f"{node}")

        try:
            translatedPolicies = []
            for policy in securityPolicies:
                print(policy)
                translatedPolicies.append(remediator.refinePolicy(policy))
            #remediator.ServiceGraph.add_filtering_rules(node, translatedPolicies)
        except Exception as ex:
            raise ex

@dataclass
class AddDnsPolicy(FunctionCall):
    """ Grammar rule for the "add_dns_policy" Recipe language command
        Sample expression: add_dns_policy for malicious_domain of type 'block_all_queries'
    """

    parent: object
    domainExpression: VarReferenceOrString
    policyTypeExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        domain = self.domainExpression.getValue(scope)
        policyType = self.policyTypeExpression.getValue(scope)
        logging.info("add_dns_policy for " + f"{domain}" + " of type " + f"{policyType}")

        try:
            remediator.ServiceGraph.add_dns_policy(domain, policyType)
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node: {self.domainExpression.getValue(scope)}, "
                f"Policy type: {self.policyTypeExpression.getValue(scope)}")

@dataclass
class AddNetworkMonitor(FunctionCall):
    """ Grammar rule for the "add_network_monitor" Recipe language command
        Sample expression: add_network_monitor behind impacted_host_ip in network_path
    """

    parent: object
    impactedNodeExpression: VarReferenceOrString
    networkPathExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        impactedNode = self.impactedNodeExpression.getValue(scope)
        networkPath = self.networkPathExpression.getValue(scope)
        logging.info("add_network_monitor behind" + f"{impactedNode}" + " in " + f"{networkPath}")

        try:
            new_node = remediator.ServiceGraph.add_network_monitor(impactedNode, networkPath)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Impacted node: {self.impactedNodeExpression.getValue(scope)}, "
                f"Network path: {self.networkPathExpression.getValue(scope)}")

@dataclass
class MoveNode(FunctionCall):
    """ Grammar rule for the "move" Recipe language command
        Sample expression:  move 'impacted_node' to 'reconfiguration_net'
    """

    parent: object
    nodeExpression: VarReferenceOrString
    subnetExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        node = self.nodeExpression.getValue(scope)
        subnet = self.subnetExpression.getValue(scope)
        logging.info("move " + f"{node}" + " to " + f"{subnet}")

        try:
            remediator.ServiceGraph.move(node, subnet)
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node: {self.nodeExpression.getValue(scope)}, "
                f"Destination subnet: {self.subnetExpression.getValue(scope)}")

@dataclass
class AddHoneypot(FunctionCall):
    """ Grammar rule for the "add_honeypot" Recipe language command
        Sample expression: add_honeypot with 'apache_vulnerability'
    """

    parent: object
    vulnerabilityExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        vulnerability = self.vulnerabilityExpression.getValue(scope)
        logging.info("add_honeypot with " + f"{vulnerability}")

        try:
            new_node = remediator.ServiceGraph.add_honeypot(vulnerability)
            scope["new_node"] = new_node
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Type of honeypot: {self.vulnerabilityExpression.getValue(scope)}")

@dataclass
class Execute(FunctionCall):
    """ Grammar rule for the "execute" Recipe language command
        Sample expression: execute 'simpleFunction'
    """

    parent: object
    functionExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        functionName = self.functionExpression.getValue(scope)
        logging.info("execute " + f"{functionName}")

        try:
            function = EnvironmentFunctions.FunctionMappings[functionName]
            function()
        except Exception as ex:
            raise ex  # just rethrow it for now

    def testRun(self, scope):
        super().info()
        print(f"Function to be executed: {self.functionExpression.getValue(scope)}")

@dataclass
class Shutdown(FunctionCall):
    """ Grammar rule for the "shutdown" Recipe language command
        Sample expression: shutdown 'compromised_host'
    """

    parent: object
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        node = self.nodeExpression.getValue(scope)
        logging.info("shutdown " + f"{node}")

        try:
            remediator.ServiceGraph.shutdown(self.nodeExpression.getValue(scope))
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node to be shutdown: {self.nodeExpression.getValue(scope)}")

@dataclass
class Isolate(FunctionCall):
    """ Grammar rule for the "isolate" Recipe language command
        Sample expression: isolate 'compromised_host'
    """

    parent: object
    nodeExpression: VarReferenceOrString

    def run(self, scope, remediator: Remediator):

        node = self.nodeExpression.getValue(scope)
        logging.info("isolate " + f"{node}")

        try:
            remediator.ServiceGraph.isolate(self.nodeExpression.getValue(scope))
        except Exception as ex:
            raise ex  # just rethrow it for now


    def testRun(self, scope):
        super().info()
        print(f"Node to be isolated: {self.nodeExpression.getValue(scope)}")


recipe_classes = [Recipe, Iteration, Condition, ListPaths, FindNode, AddFirewall, AddFilteringRules,
                    AddDnsPolicy, AddNetworkMonitor, MoveNode, AddHoneypot, EnforceSecurityPolicies,
                    Execute, Shutdown, Isolate, VarReferenceOrString, VarReference]