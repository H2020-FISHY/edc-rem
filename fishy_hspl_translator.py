import xml.etree.ElementTree as ET


def visit(root):
    for child in root:
        print(child.tag, child.attrib)
        visit(child)

def globalFind(root: ET.Element, item: str) -> ET.Element | None:
    """Retrieves the first element with name `item`, found left discending
    recursively into the tree composed of children elements of the `root`"""

    result = root.find(item)
    if result is None:
        for child in root:
            result = globalFind(child, item)
            if result is not None:
                return result
    else:
        return result

def modifyElement(root:ET.Element, item:str, value:str):
    """Sets the value of the first element called `item`, found using the globalFind function on the `root`
    element, to the value passed in `value`"""

    el = globalFind(root, item)

    el.text = value


def getFishyHSPL(hsplSubjectType, hsplSubject, hsplAction, hsplObject):

    tree = ET.parse('fishy_hspl_model.xml')
    root = tree.getroot()

    modifyElement(root, "subject", hsplSubject)

    position = globalFind(root, "reaction")
    createHSPL(position, hsplSubject, hsplAction, hsplObject)

     # re-add namespace attribute. It was taken off the xml model since namespaces seem to
     # heavily complicate xml tree altering.
    root.set("xmlns", "http://fishy-project.eu/hspl")

    ET.indent(tree, space="\t", level=0) # Indent the XML tree for better readability

    tree.write("fishy_hspl.xml")

    return tree

def addElement(position: ET.Element, element):
    """Adds a new XML element as sub-element to the element passed as the position argument"""

    position.insert(1, element)

def createHSPL(position, subject, action, object):
    """Adds a new HSPL element as sub-element of the element passed as the position argument"""

    # Create HSPL XML element
    hspl = ET.Element("hspl", attrib={"id": "hspl1"})

    # Add it to the XML model
    addElement(position, hspl)

    #Create the HSPL arguments as sub-elements of the HSPL element
    subject_el = ET.Element("subject", attrib={"type": "ip_address"})
    action_el = ET.Element("action")
    object_el = ET.Element("object")

    # Add the HSPL arguments to the XML model
    el_list = [subject_el, action_el, object_el]
    for el in el_list:
        addElement(hspl, el)

    # Set the HSPL arguments according to the arguments passed
    subject_el.text = subject
    action_el.text = action
    object_el.text = object

if __name__ == "__main__":

    getFishyHSPL("ip_address", "13.12.12.12", "is not authorized to access", "Subnet1.1")

    pass