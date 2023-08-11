import logging

def addNode(nodeName, nodeType):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new node {nodeName} deployed")

def addFirewall(newNodeName, path, capabilities):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new firewall node {newNodeName} deployed")

def add_filtering_rules(node1, iptables_rule):
    logging.info("Calling MANO API")
    logging.info("MANO API: new rule added")

def add_dns_policy(domain, rule):
    logging.info("Calling MANO API")
    logging.info("MANO API: new dns rules added")

def shutdown(node1):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: {node1} has been shutdown")

def isolate(node1):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: {node1} has been isolated")

def add_honeypot(vulnerability):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new honeypot with {vulnerability} deployed")

def add_network_monitor(newNodeName, path):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: new network monitor node {newNodeName} deployed")

def move(node1, net):
    logging.info("Calling MANO API")
    logging.info(f"MANO API: moved {node1} to {net}")

