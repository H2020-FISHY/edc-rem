#import os
#import tempfile
#from pathlib import Path
#import matplotlib.pyplot as plt
#import matplotlib.image as mpimg

import igraph as ig
import logging
import manoAPI

logging.basicConfig(level=logging.DEBUG)


globalCounters = {
    "firewall": 3,
    "switch": 2,
    "host": 12,
    "network_monitor": 0
}

# https://www.py4u.net/discuss/153391

visual_style = {}
visual_style["vertex_size"] = 10
visual_style["vertex_label"] = None
visual_style["vertex_label_size"] = 15
visual_style["vertex_label_dist"] = 3
# visual_style["vertex_shape"] = "rectangle" # don't need this, now the shape is set before saving the plot to file according to the node status
visual_style["bbox"] = (800, 800)
visual_style["edge_width"] = 0.5
visual_style["edge_label_size"] = 15
visual_style["margin"] = 100

def colorVertices(graph):
    for vertex in graph.vs:
        if vertex["nodeType"] == "firewall":
            vertex["color"] = "red"
        elif vertex["nodeType"] == "host":
            vertex["color"] = 'black'
        elif vertex["nodeType"] == "switch":
            vertex["color"] = "blue"
        elif vertex["nodeType"] == "honeypot":
            vertex["color"] = "green"
        elif vertex["nodeType"] == "network_monitor":
            vertex["color"] = "yellow"
        elif vertex["nodeType"] == "dns_server":
            vertex["color"] = "violet"
        elif vertex["nodeType"] == "gateway":
            vertex["color"] = "black"

def shapeVertices(graph):
    for vertex in graph.vs:
        if vertex["status"] == "off":
            vertex["shape"] = "circle"
        else:
            vertex["shape"] = "rectangle"

def refreshPlot1(graph):
    """Refreshes graph and sets nodes label to their name"""
    colorVertices(graph)
    shapeVertices(graph)
    visual_style["vertex_label"] = graph.vs["name"]

def refreshAndPlot1(graph):
    """Refreshes graph and plots to screen"""
    refreshPlot1(graph)
    ig.plot(graph, **visual_style)

def refreshAndSave1(graph):
    """Refreshes graph and saves it as image in png format"""
    logging.info(msg="Plotting with refreshAndSave")
    if not hasattr(refreshAndSave1, "counter"):
        refreshAndSave1.counter = 0
    refreshPlot1(graph)
    ig.plot(graph,
            target=f'graphs/graph{refreshAndSave1.counter}.png',
            **visual_style)
    refreshAndSave1.counter += 1

def refreshPlot2(graph):
    """Refreshes graph and sets nodes label to their name, plus the node ip if they have one"""
    colorVertices(graph)
    shapeVertices(graph)
    labels = []
    for vertex in graph.vs:
        if "ipAddress" in vertex.attributes() and vertex["ipAddress"] is not None:
            labels.append(str(vertex["name"] + "\n" + vertex["ipAddress"]))
        else:
            labels.append(str(vertex["name"]))
    visual_style["vertex_label"] = labels

def refreshAndSave2(graph):
    """Refreshes graph and saves it as image in png format, node names will show their ip address if they have one"""
    logging.info(msg="Plotting with refreshAndSave2")
    if not hasattr(refreshPlot2, "counter"):
        refreshPlot2.counter = 0
    refreshPlot2(graph)
    ig.plot(graph,
            target=f'graphs/graph{refreshPlot2.counter}.png',
            **visual_style)
    refreshPlot2.counter += 1

def refreshAndSave(graph):
    # CONFIGURATION -> uncomment the one to be used
    #refreshAndSave1(graph)
    refreshAndSave2(graph)
    pass


class ServiceGraph():


    def __init__(self):

        gnet1 = ig.Graph(4)
        gnet1.vs["name"] = ["host1", "host2", "host3", "switch1"]
        gnet1.add_edges([("host1", "switch1"), ("host2", "switch1"), ("host3", "switch1")])
        # gnet1.add_edges([("host1", "host2")])
        gnet1.vs["ipAddress"] = ["10.1.0.10", "10.1.0.11", "10.1.0.12", None]
        gnet1.vs["subnetMask"] = ["16", "16", "16", None]
        gnet1.vs["nodeType"] = ["host", "host", "host", "switch"]

        gnet2 = ig.Graph(4)
        gnet2.vs["name"] = ["host4", "host5", "host6", "switch2"]
        gnet2.add_edges([("host4", "switch2"), ("host5", "switch2"), ("host6", "switch2")])
        gnet2.vs["ipAddress"] = ["10.2.0.10", "10.2.0.11", "10.2.0.12", None]
        gnet2.vs["subnetMask"] = ["16", "16", "16", None]
        gnet2.vs["nodeType"] = ["host", "host", "host", "switch"]

        gnet3 = ig.Graph(4)
        gnet3.vs["name"] = ["host7", "host8", "host9", "switch_honeyNet"]
        gnet3.add_edges([("host7", "switch_honeyNet"), ("host8", "switch_honeyNet"), ("host9", "switch_honeyNet")])
        gnet3.vs["ipAddress"] = ["10.3.0.10", "10.3.0.11", "10.3.0.12", None]
        gnet3.vs["subnetMask"] = ["16", "16", "16", None]
        gnet3.vs["nodeType"] = ["honeypot", "honeypot", "honeypot", "switch"]

        gnet4 = ig.Graph(4)
        gnet4.vs["name"] = ["host10", "host11", "host12", "switch_dmz"]
        gnet4.add_edges([("host10", "switch_dmz"), ("host11", "switch_dmz"), ("host12", "switch_dmz")])
        gnet4.vs["ipAddress"] = ["10.4.0.10", "10.4.0.11", "10.4.0.12", None]
        gnet4.vs["subnetMask"] = ["16", "16", "16", None]
        gnet4.vs["nodeType"] = ["host", "host", "host", "switch"]

        self.sgraph: ig.Graph = gnet1.union([gnet2, gnet3, gnet4])

        self.sgraph.add_vertices(["switch_reconfigNet",
                                                        "firewall1",
                                                        "firewall2",
                                                        "firewall3",
                                                        "border_firewall",
                                                        "gateway",
                                                        "attacker"])

        self.sgraph.vs[self.sgraph.vs.find("switch_reconfigNet").index]["nodeType"] = "switch"
        self.sgraph.vs[self.sgraph.vs.find("firewall1").index]["nodeType"] = "firewall"
        self.sgraph.vs[self.sgraph.vs.find("firewall2").index]["nodeType"] = "firewall"
        self.sgraph.vs[self.sgraph.vs.find("firewall3").index]["nodeType"] = "firewall"
        self.sgraph.vs[self.sgraph.vs.find("firewall1").index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find("firewall2").index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find("firewall3").index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find("firewall1").index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find("firewall2").index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find("firewall3").index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find("firewall1").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
        self.sgraph.vs[self.sgraph.vs.find("firewall2").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
        self.sgraph.vs[self.sgraph.vs.find("firewall3").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["nodeType"] = "firewall"
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find("border_firewall").index]["capabilities"] = ["level_7_filtering", "level_4_filtering"]
        self.sgraph.vs[self.sgraph.vs.find("gateway").index]["nodeType"] = "gateway"
        self.sgraph.vs[self.sgraph.vs.find("attacker").index]["nodeType"] = "attacker"

        # print(self.sgraph.vs.find("host1"))

        self.sgraph.add_edge(self.sgraph.vs.find(name="switch2"), self.sgraph.vs.find(name="switch_reconfigNet"))
        self.sgraph.add_edge(self.sgraph.vs.find(name="switch1"), self.sgraph.vs.find(name="firewall1"))
        self.sgraph.add_edge(self.sgraph.vs.find(name="switch_reconfigNet"), self.sgraph.vs.find(name="firewall2"))
        self.sgraph.add_edge(self.sgraph.vs.find(name="switch_honeyNet"), self.sgraph.vs.find(name="firewall3"))
        self.sgraph.add_edge("firewall1", "border_firewall")
        self.sgraph.add_edge("firewall2", "border_firewall")
        self.sgraph.add_edge("firewall3", "border_firewall")
        self.sgraph.add_edge("switch_dmz", "border_firewall")
        self.sgraph.add_edge("border_firewall", "gateway")
        self.sgraph.add_edge("gateway", "attacker")

        webServer = self.sgraph.add_vertex(name="web_server")
        webServer["ipAddress"] = "10.5.0.10"
        webServer["subnetMask"] = "16"
        webServer["nodeType"] = "host"
        self.sgraph.add_edge("gateway", "web_server")

        dnsServer = self.sgraph.add_vertex(name="dns_server")
        dnsServer["ipAddress"] = "10.10.0.1"
        dnsServer["subnetMask"] = "16"
        dnsServer["nodeType"] = "dns_server"
        dnsServer["dns_rules"] = []
        self.sgraph.add_edge("border_firewall", "dns_server")

        self.sgraph.vs["status"] = "on" # set all nodes' status to on

        ## Tests for list_path correction
        #self.sgraph.add_edges([("switch1", "switch_dmz")])
        #self.sgraph.add_edges([("host1", "host2")])
        ##

        ## Tests for scalability of the graph with subnet size of hundreds of nodes
        # print(gsgraph.vs[0].attributes())

        # Example relocation
        # refreshAndSave(self.sgraph)

        # hostToRelocate = "host1"
        # edgesToRemove = self.sgraph.es.select(_source=hostToRelocate)
        # self.sgraph.delete_edges(edgesToRemove)
        # refreshAndSave(self.sgraph)

        # self.sgraph.add_edge(source=hostToRelocate, target="switch_reconfigNet")
        # refreshAndSave(self.sgraph)

        # ind = 0
        # while ind < 9:
        #     ind += 1
        #     el = self.sgraph.add_vertex(f"host{ind+100}")
        #     #self.sgraph.add_edge(f"host{ind+100}", "gateway")
        #     self.sgraph.add_edge(f"host{ind+100}", "border_firewall")
        #     el["ipAddress"] = f"10.1.0.{ind+100}"
        #     el["subnetMask"] = "16"
        #     el["nodeType"] = "host"

        # ind = 0
        # while ind < 1000:
        #     ind += 1
        #     el = self.sgraph.add_vertex(f"hostt{ind+100}")
        #     self.sgraph.add_edge(f"hostt{ind+100}", "gateway")
        #     el["nodeType"] = "host"
        ##

    def plot(self):
        refreshAndSave(self.sgraph)

    def returnNodeName(self, nodeIdentifier):
        # this is a utility function used to quickly address the issue of accepting both node names and
        # ip addresses arguments given to functions in the recipes

        # for v in self.sgraph.vs:
        #     print(str(v["name"]) + " " + str(v["ipAddress"]))

        try:
            nodeName = self.sgraph.vs.find(ipAddress=nodeIdentifier)
            return nodeName["name"]
        except ValueError:
            return nodeIdentifier

    def list_paths(self, srcNode, dstNode): # return a list of node paths
        logging.info(msg="Searching for paths ...")
        srcNode = self.returnNodeName(srcNode)
        dstNode = self.returnNodeName(dstNode)
        paths = self.sgraph.get_all_simple_paths(srcNode, to=dstNode)
        logging.info(msg=f"Found {len(paths)} paths")
        node_paths = [ self.sgraph.vs[el]["name"] for el in paths ]
        logging.info(msg="Converted paths from node ids to node names")
        secondPositionNodes = set()
        for path in node_paths:
            secondPositionNodes.add(path[1])
        pruned_paths = []
        for nodeName in secondPositionNodes:
            for path in node_paths:
                if path[1] == nodeName:
                    pruned_paths.append(path)
                    break
        logging.info(msg="Pruned equivalent paths, that is consider only paths with different nodes attached to the srcNode")
        return pruned_paths

    def find_node_in_path(self, path, nodeType, capabilities): # return node name
        logging.info(msg=f"Searching for a node of {nodeType} type in this path: {path} ...")
        for el1 in path:
            node: ig.Vertex = self.sgraph.vs.find(el1)
            if node["nodeType"] == nodeType:
                # print(node)
                # print(node["capabilities"])
                checkRequestedCapabilities = all(el2 in node["capabilities"] for el2 in capabilities)
                if checkRequestedCapabilities:
                    logging.info(msg=f"Found node named {node['name']} of {nodeType} type in the path with capabilities requested: {capabilities}")
                    return node["name"]
        logging.info(msg=f"No node of {nodeType} type found in the path with capabilities requested: {capabilities}")
        return "Not found"

    def add_node(self, node1, node2, nodeType): # add node between node1 and node2

        node1 = self.returnNodeName(node1)
        node2 = self.returnNodeName(node2)

        logging.info(msg=f"Adding a node of type {nodeType} between {node1} and {node2} ...")
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.get_eid(node1, node2))
        logging.info(msg=f"Removed edge from {node1} to {node2}")
        refreshAndSave(self.sgraph)
        globalCounters[nodeType] += 1
        newNodeName = f"{nodeType}{globalCounters[nodeType]}"
        self.sgraph.add_vertex(name=newNodeName, nodeType=nodeType)
        logging.info(msg=f"Added node of type {nodeType} to graph named {newNodeName}")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
        logging.info(msg=f"Added an edge between {node1} and {newNodeName}")
        logging.info(msg=f"Added an edge between {newNodeName} and {node2}")
        refreshAndSave(self.sgraph)
        manoAPI.addNode(node1, nodeType)

        # print(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_firewall(self, node1, path, capabilities): # add firewall behind "node" on the "path"

        logging.info(msg=f"Adding a firewall node behind {node1} ...")
        node1 = self.returnNodeName(node1)
        for index, item in enumerate(path): # first find node to which node1 is connected
            if item == node1:
                node2 = path[index+1]
                break

        logging.info(msg=f"Searching node behind {node1}")
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.get_eid(node1, node2))
        logging.info(msg=f"Deleted edge between {node1} and {node2}")
        refreshAndSave(self.sgraph)
        globalCounters["firewall"] += 1
        newNodeName = f"firewall{globalCounters['firewall']}"
        self.sgraph.add_vertex(name=newNodeName, nodeType="firewall")
        self.sgraph.vs[self.sgraph.vs.find(newNodeName).index]["rules_level_4"] = []
        self.sgraph.vs[self.sgraph.vs.find(newNodeName).index]["rules_level_7"] = []
        self.sgraph.vs[self.sgraph.vs.find(newNodeName).index]["capabilities"] = capabilities
        logging.info(msg="Added firewall node to graph")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
        logging.info(msg=f"Added an edge between {node1} and {newNodeName}")
        logging.info(msg=f"Added an edge between {newNodeName} and {node2}")
        refreshAndSave(self.sgraph)
        manoAPI.addFirewall(newNodeName, path, capabilities)

        # print(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_filtering_rules(self, node1, rules):

        logging.info(msg=f"Adding new rules to {node1} ...")

        node1 = self.returnNodeName(node1)
        node: ig.Vertex = self.sgraph.vs.find(node1)
        logging.info(msg=f"Got reference to {node1}")
        for rule in rules:
            if rule["type"] == "level_4_filtering":
                if "level_4_filtering" in node["capabilities"]:
                    node["rules_level_4"].append(rule)
                    manoAPI.add_filtering_rules(node1, rule)
                    logging.info(msg=f"Added new level 4 rule to {node1}: {rule}")
                else:
                    logging.info("This firewall doesn't support level 4 filtering!")
                    break
            else:
                if "level_7_filtering" in node["capabilities"]:
                    node["rules_level_7"].append(rule)
                    manoAPI.add_filtering_rules(node1, rule)
                    logging.info(msg=f"Added new level 7 rule to {node1}: {rule}")
                else:
                    logging.info("This firewall doesn't support level 7 filtering!")
                    break
        print(node)

    def add_dns_policy(self, domain, rule_type):

        logging.info(msg="Adding new rule to dns_server ...")
        rule = {"domain": domain, "action": rule_type}
        node1 = "dns_server"
        node: ig.Vertex = self.sgraph.vs.find(node1)
        logging.info(msg=f"Got reference to {node1}")
        node["dns_rules"].append(rule)
        logging.info(msg=f"Added new rule to {node1}: {rule}")

        print(node)
        manoAPI.add_dns_policy(domain, rule_type)


    def shutdown(self, node1):

        logging.info(msg=f"Shutting down {node1} ...")

        node1 = self.returnNodeName(node1)
        refreshAndSave(self.sgraph)
        node: ig.Vertex = self.sgraph.vs.find(node1)
        logging.info(msg=f"Got reference to {node1}")
        node["status"] = "off"
        logging.info(msg=f"Set status of {node1} to off")
        refreshAndSave(self.sgraph)
        manoAPI.shutdown(node1)

    def isolate(self, node1):

        logging.info(msg=f"Disconnecting all interfaces of {node1} ...")

        node1 = self.returnNodeName(node1)
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.es.select(_source=node1))
        logging.info(msg=f"Deleted all edges from {node1}")
        refreshAndSave(self.sgraph)
        manoAPI.isolate(node1)

    def add_honeypot(self, vulnerability):

        logging.info(msg="Adding a new honeypot node to the honey net ...")
        refreshAndSave(self.sgraph)
        globalCounters["host"] += 1
        newNodeName = f"host{globalCounters['host']}"
        node = self.sgraph.add_vertex(name=newNodeName, nodeType="honeypot")
        logging.info(msg="Added honeypot node to graph")
        if "vulnerabilityList" in node.attributes() and node["vulnerabilityList"] is not None:
            node["vulnerabilityList"] += f"/{vulnerability}"
        else:
            node["vulnerabilityList"] = vulnerability
        logging.info(msg="Added vulnerability list to honeypot node")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(newNodeName, "switch_honeyNet")])
        logging.info(msg="Added edge between honeypot and honey net switch")
        refreshAndSave(self.sgraph)
        manoAPI.add_honeypot(vulnerability)

        # print(self.sgraph.vs.find(newNodeName).attributes())

        return newNodeName

    def add_network_monitor(self, node1, path): # add network monitor behind "node" on the "path"

        logging.info(msg=f"Adding network monitor node behind {node1} in this path {path} ...")

        node1 = self.returnNodeName(node1)
        for index, item in enumerate(path): # first find node to which node1 is connected
            if item == node1:
                node2 = path[index+1]
                break

        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.get_eid(node1, node2))
        logging.info(msg=f"Deleted edge between {node1} and {node2}")
        refreshAndSave(self.sgraph)
        globalCounters["network_monitor"] += 1
        newNodeName = f"network_monitor{globalCounters['network_monitor']}"
        self.sgraph.add_vertex(name=newNodeName, nodeType="network_monitor")
        logging.info(msg="Added netowork monitor node to graph")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, newNodeName), (newNodeName, node2)])
        logging.info(msg=f"Added an edge between {node1} and {newNodeName}")
        logging.info(msg=f"Added an edge between {newNodeName} and {node2}")
        refreshAndSave(self.sgraph)
        # print(self.sgraph.vs.find(newNodeName).attributes())
        manoAPI.add_network_monitor(newNodeName, path)

        return newNodeName

    def move(self, node1, net): # moves a node to another location

        logging.info(msg=f"Moving {node1} to {net} ...")

        if net == "reconfiguration_net":
            switch = "switch_reconfigNet"
        node1 = self.returnNodeName(node1)
        refreshAndSave(self.sgraph)
        self.sgraph.delete_edges(self.sgraph.es.select(_source=node1))
        logging.info(msg=f"Deleted all edges from {node1}")
        refreshAndSave(self.sgraph)
        self.sgraph.add_edges([(node1, switch)])
        logging.info(msg=f"Added edge from {node1} to {switch}")
        refreshAndSave(self.sgraph)
        # print(self.sgraph.vs.find(newNodeName).attributes())
        manoAPI.move(node1, net)


if __name__ == "__main__":

    pass
