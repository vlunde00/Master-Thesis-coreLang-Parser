import maltoolbox
from maltoolbox.language import classes_factory
from maltoolbox.language import specification
from maltoolbox.attackgraph import attackgraph
from maltoolbox.model import model as malmodel
from maltoolbox.ingestors import neo4j

import json

'''
Set up twin_view json

'''

twin_view = open('./workspace.json', 'r', newline='')
twin_view_json = json.loads(twin_view.read())

'''
Boilerplate for loading coreLang via the toolbox.

'''
lang_file = 'org.mal-lang.coreLang-1.0.0.mar' # malc produces .mar files
lang_spec = specification.load_language_specification_from_mar(lang_file)
specification.save_language_specification_to_json(lang_spec, 'lang_spec.json')
lang_classes_factory = classes_factory.LanguageClassesFactory(lang_spec)
lang_classes_factory.create_classes()

'''
Set up twin_view model.

'''
model = malmodel.Model('Twin View Model', lang_spec, lang_classes_factory)


'''
Build models here

'''

hosts = {}
users = {}
ids = {}
applications = {}
networks = {}
hardware = {}
creds = {}
connections = {}
entrypoints1 = []
entrypoints2 = []
entrypoints3 = []

# example attackers, since json specs does not contain any attacker info
attacker1 = malmodel.Attacker() # social-engineering
attacker2 = malmodel.Attacker() # denial-of-service on network
attacker3 = malmodel.Attacker() # physical access to hardware in hospital

people = twin_view_json['model']['people']
deploymentNodes = twin_view_json['model']['deploymentNodes'] 

# There are a lot of assumptions here due to a lack of info in the json specs of the system
# This parser is made to work with json specs of TwinView, which were downloaded in early February

# Print details of people
for person in people:

    ids[person['id']] = lang_classes_factory.ns.Identity(name = person['name']) # using name as approximation of identity
    model.add_asset(ids[person['id']])

    for node in deploymentNodes:
        networks[node['id']] = lang_classes_factory.ns.Network(name = node['name']) # assuming networks are always children of deploymentNodes
        model.add_asset(networks[node['id']]) 

        entrypoints2.append((networks[node['id']], ['deny']))
        for device in node['children']: # assuming devices are children of networks
            hardware[device['id']] = lang_classes_factory.ns.Hardware(name = device['name'])
            model.add_asset(hardware[device['id']])

            entrypoints3.append((hardware[device['id']], ['physicalAccess']))
            if "children" in device:
                for software in device['children']: # assuming software are always children under devices
                    applications[software['id']] = lang_classes_factory.ns.Application(name = software['name'])
                    model.add_asset(applications[software['id']])

                    sysexec =\
                        lang_classes_factory.ns.SysExecution(
                        hostHardware = [hardware[device['id']]],
                        sysExecutedApps = [applications[software['id']]]
                        )
                    model.add_association(sysexec) # assuming devices executes all children, which are software

                    exec_id_app_assoc =\
                        lang_classes_factory.ns.ExecutionPrivilegeAccess(
                        executionPrivIAMs = [ids[person['id']]],
                        execPrivApps = [applications[software['id']]]
                        )
                    model.add_association(exec_id_app_assoc) # assuming the identities have execution privileges to all software of the devices

                    creds[software['id']] = lang_classes_factory.ns.Credentials(name = 'Creds' +  ' ' + software['name']) # examples credentials, since there are not any present in the json specs

                    creds[software['id']].notGuessable = 0.0 # assuming worst case scenario since this info is not present in json
                    creds[software['id']].unique = 0.0
                    creds[software['id']].notDisclosed = 0.0
                    creds[software['id']].notPhishable = 0.0

                    #entrypoints1.append((creds[software['id']], ['attemptCredentialsReuse', 'guessCredentials', 'useLeakedCredentials']))

                    model.add_asset(creds[software['id']])

                    id_creds_app_assoc=\
                        lang_classes_factory.ns.IdentityCredentials(
                        identities = [ids[person['id']]],
                        credentials = [creds[software['id']]]
                        )
                    model.add_association(id_creds_app_assoc) # assuming all software uses credentials

                    if "softwareSystemInstances" in software:
                        for instance in software['softwareSystemInstances']:
                            applications[instance['id']] = applications[software['id']] # generalize the softwareSystemInstances as being the same as software, in order to get model simplicity
                            if "relationships" in instance:
                                for relationship in instance['relationships']:
                                    if "technology" in relationship:
                                        connections[relationship['id']] = lang_classes_factory.ns.ConnectionRule(name = device['name'] + " " + software['name'] + " " + relationship['technology']) # clarify in attack graph what connection belongs to what software and device
                                        model.add_asset(connections[relationship['id']])

                                        appcon_software_tech =\
                                            lang_classes_factory.ns.ApplicationConnection(
                                            applications = [applications[software['id']]],
                                            appConnections = [connections[relationship['id']]]
                                            )
                                        model.add_association(appcon_software_tech)

                                        netcon_crs_net_assoc =\
                                            lang_classes_factory.ns.NetworkConnection(
                                            netConnections = [connections[relationship['id']]],
                                            networks = [networks[node['id']]]
                                            )
                                        model.add_association(netcon_crs_net_assoc) # since application is child of network, assume it is directly conected to network

                    if "containerInstances" in software:
                        for instance in software['containerInstances']:
                            applications[instance['id']] = applications[software['id']] # generalization, similar reasons as above
                            if "relationships" in instance:
                                for relationship in instance['relationships']:
                                    if "technology" in relationship:
                                        connections[relationship['id']] = lang_classes_factory.ns.ConnectionRule(name = device['name'] + " " + software['name'] + " " + relationship['technology'])
                                        model.add_asset(connections[relationship['id']])

                                        appcon_software_tech =\
                                            lang_classes_factory.ns.ApplicationConnection(
                                            applications = [applications[software['id']]],
                                            appConnections = [connections[relationship['id']]]
                                            )
                                        model.add_association(appcon_software_tech)

                                        netcon_crs_net_assoc =\
                                            lang_classes_factory.ns.NetworkConnection(
                                            netConnections = [connections[relationship['id']]],
                                            networks = [networks[node['id']]]
                                            )
                                        model.add_association(netcon_crs_net_assoc)
        
    users[person['id']] = lang_classes_factory.ns.User(name = person['description']) # using description as approximation of user
    users[person['id']].noPasswordReuse = 0.0 # assume worst case scenario since ther is lack of info in the json specs
    users[person['id']].securityAwareness = 0.0
    model.add_asset(users[person['id']])

    entrypoints1.append((users[person['id']], ['socialEngineering']))

    user_id_assoc =\
        lang_classes_factory.ns.UserAssignedIdentities(
        users = [users[person['id']]],
        userIds = [ids[person['id']]]
        )
    model.add_association(user_id_assoc)


softwareSystems = twin_view_json['model']['softwareSystems']

for softwareSystem in softwareSystems:
    applications[softwareSystem['id']] = lang_classes_factory.ns.Application(name = softwareSystem['name'])
    model.add_asset(applications[softwareSystem['id']])
    if "relationships" in softwareSystem:
        for relationship in softwareSystem['relationships']:
            if "technology" in relationship:
                    connections[relationship['id']] = lang_classes_factory.ns.ConnectionRule(name = softwareSystem['name'] + " " + relationship['technology'])
                    model.add_asset(connections[relationship['id']])

                    appcon_softwareSys_tech =\
                        lang_classes_factory.ns.ApplicationConnection(
                        applications = [applications[softwareSystem['id']]],
                        appConnections = [connections[relationship['id']]]
                        )
                    model.add_association(appcon_softwareSys_tech)


# Add relationship associations
                    
for softwareSystem in softwareSystems:
    if "relationships" in softwareSystem:
        for relationship in softwareSystem['relationships']:
            if relationship['destinationId'] in applications.keys():
                # Software executes another software
                appexec =\
                        lang_classes_factory.ns.AppExecution(
                        hostApp = [applications[relationship['sourceId']]],
                        appExecutedApps = [applications[relationship['destinationId']]]
                        )
                model.add_association(appexec)


for person in people:
    if "relationships" in person:
        for relationship in person['relationships']:
            if relationship['destinationId'] in applications.keys():
                # Identity executes another software
                id_appexec =\
                        lang_classes_factory.ns.ExecutionPrivilegeAccess(
                        executionPrivIAMs = [ids[relationship['sourceId']]],
                        execPrivApps = [applications[relationship['destinationId']]]
                        )
                model.add_association(id_appexec)
            
            if relationship['destinationId'] in hardware.keys():
                # User access to hardware
                user_hardware =\
                        lang_classes_factory.ns.HardwareAccess(
                        users = [users[relationship['sourceId']]],
                        hardwareSystems = [hardware[relationship['destinationId']]]
                        )
                model.add_association(user_hardware)


for node in deploymentNodes:
        for device in node['children']:
            if "children" in device:
                for software in device['children']:

                    if "softwareSystemInstances" in software:
                        for instance in software['softwareSystemInstances']:
                            if "relationships" in instance:
                                for relationship in instance['relationships']:
                                    if relationship['destinationId'] in applications.keys():
                                        # Software executes another software
                                        appexec =\
                                                lang_classes_factory.ns.AppExecution(
                                                hostApp = [applications[software['id']]],
                                                appExecutedApps = [applications[relationship['destinationId']]]
                                                )
                                        model.add_association(appexec)                                        

                    if "containerInstances" in software:
                        for instance in software['containerInstances']:
                            if "relationships" in instance:
                                for relationship in instance['relationships']:
                                    if relationship['destinationId'] in applications.keys():
                                        # Software executes another software
                                        appexec =\
                                                lang_classes_factory.ns.AppExecution(
                                                hostApp = [applications[software['id']]],
                                                appExecutedApps = [applications[relationship['destinationId']]]
                                                )
                                        model.add_association(appexec)

            if "softwareSystemInstances" in device:
                for instance in device['softwareSystemInstances']:
                    if "relationships" in instance:
                        for relationship in instance['relationships']:
                            if relationship['destinationId'] in applications.keys():
                                # Hardware executes software
                                sysexec =\
                                        lang_classes_factory.ns.SysExecution(
                                        hostHardware = [hardware[device['id']]],
                                        sysExecutedApps = [applications[relationship['destinationId']]]
                                        )
                                model.add_association(sysexec)   
                                        
attacker1.entry_points = entrypoints1
attacker2.entry_points = entrypoints2
attacker3.entry_points = entrypoints3
model.add_attacker(attacker1)
model.add_attacker(attacker2) 
model.add_attacker(attacker3)        
'''
Save models as JSON.

'''
model.save_to_file('twin_view_model.json')
graph = attackgraph.AttackGraph()
graph.generate_graph(lang_spec, model)
graph.attach_attackers(model)
graph.save_to_file('twin_view_attack_graph.json')

'''
Neo4J boilerplate.

The Neo4J config can be under maltoolbox/default.conf.

'''
# My local Neo4J creds
maltoolbox.neo4j_configs['uri'] = 'bolt://localhost:7687'
maltoolbox.neo4j_configs['username'] = 'neo4j'
maltoolbox.neo4j_configs['password'] = 'dynp12345'
maltoolbox.neo4j_configs['dbname'] = 'neo4j'

# Dump to Neo4J
neo4j.ingest_model(model,
    maltoolbox.neo4j_configs['uri'],
    maltoolbox.neo4j_configs['username'],
    maltoolbox.neo4j_configs['password'],
    maltoolbox.neo4j_configs['dbname'],
    delete=True)

# Comment out this block to skip the big attack graph.
neo4j.ingest_attack_graph(graph,
    maltoolbox.neo4j_configs['uri'],
    maltoolbox.neo4j_configs['username'],
    maltoolbox.neo4j_configs['password'],
    maltoolbox.neo4j_configs['dbname'],
    delete=False)
