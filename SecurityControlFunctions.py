#from iptables_translator import getIptablesCommand

#this function is a stub, just return the rule
def generic_level_7_filter_command_generator(rule, *args):
    del args # just to hide the alert about the arg not being used

    return rule

#this function is a stub, just return the rule
def generic_network_traffic_monitor_command_generator(rule, *args):
    del args # just to hide the alert about the arg not being used

    return rule

# def iptables_comand_generator(rule, *args):
#     del args # just to hide the alert about the arg not being used
#     generatedRule = getIptablesCommand(rule["victimIP"],
#                                             rule["c2serversIP"],
#                                             rule["c2serversPort"],
#                                             rule["proto"],
#                                             "FORWARD")

#     return generatedRule

def testFunction(*args):
    del args
    if not hasattr(testFunction, "counter"):
        testFunction.counter = 0

    if testFunction.counter == 0:
        return "regola 1"
    elif testFunction.counter == 1:
        return "regola 2"
    elif testFunction.counter == 2:
        return "regola 3"

    testFunction.counter += 1

FunctionMappings = {
    "iptables": testFunction, #iptables_comand_generator #testFunction
    "generic_level_7_filter": generic_level_7_filter_command_generator,
    "generic_network_traffic_monitor": generic_network_traffic_monitor_command_generator
}