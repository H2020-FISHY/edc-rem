from dataclasses import dataclass
import textx
from textx.export import model_export, metamodel_export

from remediator import Remediator

from . import grammar_classes
from .grammar_classes import recipe_classes

@dataclass
class Interpreter:

    globalScope: object
    recipeFile: str
    remediator: Remediator

    def launch(self):

        # As "classes" argument the list of custom classes must be passed. Sometimes, if not all grammar
        # rules defined in the grammar.tx have a corresponding custom class, just passing them as a list
        # doesn't work. Throws an exception.
        # Another method must be used in this case, such as passing them with the dereferencing operator or
        # alternatively using the method shown in the textx documentation.
        recipe_mm = textx.metamodel_from_file('recipe_language/grammar.tx', classes=recipe_classes)
        metamodel_export(recipe_mm, "recipe_language/recipe_metamodel.dot")

        ### How to get an image of the metambodel schema with a layout with readable edges' labels
        ### from the recipe_metamodel.dot file:
        ### Modify all the "headlabel" occurrences in the recipe_metamodel.dot file with "taillabel"
        ### Use this GraphViz command:
        ### dot -Eminlen=5 -Elabeldistance=10 -Grankdir="LR" -Tpng -O recipe_metamodel.dot
        ###
        ###

        recipe_m: grammar_classes = recipe_mm.model_from_file(self.recipeFile)
        model_export(recipe_m, "recipe_language/recipe_model.dot")

        recipe_m.run(self.globalScope, self.remediator)

if __name__ == "__main__":


    globalScope = {"impacted_host_ip": "prova_impatto",
                   "path_list": ["Prova1", "prova2", "prova3"],
                   "found": True,
                }
    recipeFile = 'recipes/test2.rec'


    interpreter = Interpreter(globalScope, recipeFile)
    interpreter.launch()