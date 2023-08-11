filter_payload_recipe_old = "list_paths from 'host1' to 'attacker'\n                                               \
     iterate_on path_list\n                                                                                        \
         find_node of type 'filtering_node'\n                                                                      \
         if not found:\n                                                                                           \
             add_node of type 'filtering_node' between impacted_node and threat_source\n                           \
             add_rule attack_payload to new_node payload filtering list\n                                          \
         else\n                                                                                                    \
             add_rule attack_payload to filtering_node payload filtering list\n                                    \
         endif\n                                                                                                   \
     enditeration"

# recipe for nested "iterate" and "if" constructs testing.
interpreterTest1 = "iterate_on listTest1\n                                                                         \
         invertCondizioneTest other optional keywords and parameters\n                                             \
         iterate_on listTest2\n                                                                                    \
             actionThatDoesNothing other optional keywords and parameters\n                                        \
             if condizioneTest\n                                                                                   \
                 testIf other optional keywords and parameters\n                                                   \
             else\n                                                                                                \
                 testElse other optional keywords and parameters\n                                                 \
             endif\n                                                                                               \
         enditeration\n                                                                                            \
     enditeration"

# test recipe for nested loops, executes 3*3*3*3 = 81 times the testIf function which just prints a log
interpreterTest3= "iterate_on listTest1\n\
                         iterate_on listTest1\n\
                             iterate_on listTest1\n\
                                 iterate_on listTest1\n\
                                     testIf \n\
                                 enditeration \n\
                             enditeration \n\
                         enditeration \n\
                     enditeration"