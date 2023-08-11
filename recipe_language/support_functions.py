def getVarFromContext(key, scope):
    # gets the value of a given variable from its key, that is its name, searching starting from the innermost scope
    if key in scope:
        return scope[key]
    elif "outerScope" in scope:
        return getVarFromContext(key, scope["outerScope"])
    else:
        #raise Exception(f"Can't find this variable in the program stack: {key}")
        return "Value undefined"