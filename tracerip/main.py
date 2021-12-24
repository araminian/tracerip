from re import sub
from tracerip.utils.report.network import *
from tracerip.utils.nacl.IPUtils import *
import kopf

from kubernetes import client, config
from kubernetes.client.rest import ApiException

@kopf.on.delete('networks.tracerip.io')
def delete_network_fn(spec, name, namespace, logger, **kwargs):
    network = "{0}-{1}".format(name,namespace)
    deleteResult = removeNetwork(Network=network)

    if(type(deleteResult) == dict):
        if(deleteResult['ErrorCode'] == '300'):
            pass
        else:
            logger.error(deleteResult['ErrorMsg'])
            raise kopf.TemporaryError(deleteResult['ErrorMsg'])
    
    if(deleteResult == True):
        logger.info("The network '{0}' is removed".format(name))


@kopf.on.create('networks.tracerip.io')
def create_network_fn(spec, name, namespace, logger, **kwargs):

    CIDR = spec.get('CIDR')
    if not CIDR:
        logger.error('CIDR Must be set')
        raise kopf.PermanentError('Network CIDR must be set and is mandatory.')
        
    # Check Valid CIDR
    Linter = False
    validCIDR = isValidCIDR(CIDR=CIDR)
    if(type(validCIDR) == dict and 'ErrorMsg' in validCIDR):
        logger.error(validCIDR['ErrorMsg'])
        Linter = True
    
    # Check Reserved Range
    reservedRange = spec.get('ReservedRange')
    if (reservedRange):
        
        rangeParts = reservedRange.split('-')
        ## Check ReservedRange in a good format 'Start-End'
        if (len(rangeParts) != 2):
            Linter = True
            logger.error("Invalid ReservedRange format '{0}'".format(reservedRange))
            raise kopf.PermanentError("Invalid ReservedRange format '{0}'".format(reservedRange))

        ## Check start of range is Valid IP
        startValid = False
        endValid = False
        isStartRangeValid = isValidIP(IP=rangeParts[0])
        if (type(isStartRangeValid) == dict and 'ErrorMsg' in isStartRangeValid ):
            logger.error("The start IP '{0}' of ReservedRange is not valid IP Address".format(rangeParts[0]))
            Linter = True
        else:
            ## Check start of range inside CIDR
            startValid = True
            isStartRangeInCIDR = isIPinCIDR(CIDR=CIDR,IP=rangeParts[0])
            if (not isStartRangeInCIDR):
                logger.error("The start '{0}' of ReservedRange is not inside of CIDR '{1}".format(rangeParts[0],CIDR))
                Linter = True

        ## Check end of range is Valid IP
        isEndRangeValid = isValidIP(IP=rangeParts[1])
        if(type(isEndRangeValid) == dict and 'ErrorMsg' in isEndRangeValid):
            logger.error("The end IP '{0}' of ReservedRange is not valid IP Address".format(rangeParts[0]))
            Linter = True
        else:
            ## Check end of range inside CIDR
            endValid = True
            isEndRangeInCIDR = isIPinCIDR(CIDR=CIDR,IP=rangeParts[1])
            if (not isEndRangeInCIDR):
                logger.error("The end '{0}' of ReservedRange is not inside of the CIDR '{1}'".format(rangeParts[1],CIDR))
                Linter = True
        
        ## Check start of range smaller than end of range
        if (startValid and endValid):
            if (not isIPSmallerThan(smallIP=rangeParts[0],bigIP=rangeParts[1])):
                logger.error("The start '{0}' of ReservedRange is bigger than end '{1}' of ReservedRange".format(rangeParts[0],rangeParts[1]))
                Linter = True

    reservedIPs = spec.get('ReservedIPs')

    if(reservedIPs):

        # Check the Reserved IPs are Valid

        for ip in reservedIPs:
            
            isIPValid = isValidIP(IP=ip)
            if (type(isIPValid) == dict and 'ErrorMsg' in isIPValid):
                logger.error("The Reserved IP '{0}' is not valid IP Address".format(ip))
                Linter = True
            else:
                # Check the IP is in the CIDR
                isIPInside = isIPinCIDR(CIDR=CIDR,IP=ip)
                if(not isIPInside):
                    logger.error("The Reserved IP '{0}' is not inside of the CIDR '{1}'".format(ip,CIDR))
                    Linter = True
    
    if(Linter):
        raise kopf.PermanentError('Lint failed')

    network = "{0}-{1}".format(name,namespace)

    initialResult = initializeSubnet(
        Network=network,
        CIDR=CIDR,
        ReservedRange=reservedRange,
        ReservedIPs=reservedIPs
    )

    if(type(initialResult) == dict and 'ErrorMsg' in initialResult):
        logger.error(initialResult['ErrorMsg'])
        raise kopf.TemporaryError('Network initialization failed')
    
    if(initialResult == True):
        logger.info('Network initialization done')

@kopf.on.delete('ips.tracerip.io')
def delete_ip_fn(spec, name, namespace, logger, **kwargs):

    network = spec.get('Network')
    
    configMapName = "{0}.tracerip".format(name)

    networkNamespace = "{0}-{1}".format(network,namespace)


    #config.load_kube_config()
    core_v1_api = client.CoreV1Api()

    returnedIP = returnIP(Network=networkNamespace,clientName=name)

    if(type(returnedIP) == dict and 'ErrorMsg' in returnedIP):
        
        logger.error(returnedIP['ErrorMsg'])
        raise kopf.PermanentError("can't be deleted")
    
    if(returnedIP != True):
        raise kopf.PermanentError("Can't be deleted")

    label_selector="Managed-by=tracerIP,Network={0},Client={1}".format(network,name)

    isConfigMapDeleted = False
    try:
        configMapList = core_v1_api.list_namespaced_config_map(namespace=namespace,label_selector=label_selector)
        if(len(configMapList.items) == 0):
            isConfigMapDeleted = True
            logger.info("The ConfigMap {0} was deleted manually".format(configMapName))

    except ApiException as e:
        raise kopf.PermanentError("Can't access k8s API Server: %s\n" % e)

    if(not isConfigMapDeleted):
        try:
            core_v1_api.delete_namespaced_config_map(
                name=configMapName,
                namespace=namespace
            )
        except ApiException as e:
            raise kopf.PermanentError("Can't delete configMap: %s\n" % e)



@kopf.on.create('ips.tracerip.io')
def create_ip_fn(spec, name, namespace, logger, **kwargs):

    network = spec.get('Network')

    if not network:
        logger.error('Network must be set')
        raise kopf.PermanentError('Network must be set and is mandatory.')
    
    networkNamespace = "{0}-{1}".format(network,namespace)
    Linter = False

    isInitialized = isNetworkInitialized(Network=networkNamespace)

    if (type(isInitialized) == dict):
        logger.error("ERROR: {0}".format(isInitialized['ErrorMsg']))
        raise kopf.PermanentError('Lint failed')
    if (type(isInitialized) == tuple and not isInitialized[0]):
        logger.error("ERROR: The network {0} is not initialized".format(network))
        raise kopf.PermanentError('Lint failed')
    
    
    ip = spec.get('IPAddress')

    subnetInfo = get_all_entries(database_name=networkNamespace,table_name='subnet')
    if(type(subnetInfo) == dict and 'ErrorMsg' in subnetInfo):
        logger.error(subnetInfo['ErrorMsg'])
        raise kopf.PermanentError("Can't access database")

    subnetInfo = list(subnetInfo['Enteries'])[0]

    if ip:
    # Check IP is valid
        IPValid = isValidIP(IP=ip)
        if(type(IPValid) == dict and 'ErrorMsg' in IPValid):
            logger.error("The IP '{0}' is not valid IP Address".format(ip))
            Linter = True
        else:
            
            IPisInReservedRange = True
            IPisInReservedIPs = True
            # Check if IP is in Reserved Range
            if('reservedRange' in subnetInfo):
                reservedRange = subnetInfo['reservedRange'].split('-')
                ipInRange = isIPinRange(range=reservedRange,IP=ip)
                if (not ipInRange):
                    IPisInReservedRange = False

            # Check if IP is in Reserved IPs
            if('reservedIPs' in subnetInfo):
                reservedIPs = subnetInfo['reservedIPs'].split(',')
                if(ip not in reservedIPs):
                    IPisInReservedIPs = False

            if(not IPisInReservedIPs and not IPisInReservedRange):
                Linter = True
                logger.error("The IP '{0}' is not in the reserved range or reserved IPs".format(ip))
            

    if(Linter):
        raise kopf.PermanentError('Lint failed')
    

    requestedIP = requestIP(
        Network=networkNamespace,
        clientName=name,
        IP=ip
    )
    
    if(type(requestedIP) == dict):

        logger.error("ERROR : {0}".format(requestedIP['ErrorMsg']))
        
        if(requestedIP['ErrorCode'] == '805'):
            raise kopf.TemporaryError("Can't request IP for client")
        
        raise kopf.PermanentError("Can't request IP for client")


    # Create a configmap

    configMapName = "{0}.tracerip".format(name)
    metadata = client.V1ObjectMeta(
        name=configMapName,
        namespace=namespace,
        labels={
            "Managed-by": 'tracerIP',
            "Network": network,
            "Client" : name
        }
    )

    configmap = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        data=dict(IP="{0}".format(requestedIP)),
        metadata=metadata
    )

    #kopf.adopt(configmap)
    #config.load_kube_config()
    core_v1_api = client.CoreV1Api()

    try:
        core_v1_api.create_namespaced_config_map(
            namespace=namespace,
            body=configmap
        )
    except ApiException as e:
        raise kopf.PermanentError("Can't create configMap: %s\n" % e)

    logger.info("ConfigMap is created: {0}".format(configMapName))
    return {'ConfigMap-name': configMapName}
        
@kopf.on.field('ips.tracerip.io', field='spec.IPAddress')
def ipUpdate(name, old,new,spec,status,logger, namespace, **kwargs):
  
    network = spec.get('Network')
    namespacedNetowrk = "{0}-{1}".format(network,namespace)

    isInitialized = isNetworkInitialized(Network=namespacedNetowrk)

    if (type(isInitialized) == dict):
        logger.error("ERROR: {0}".format(isInitialized['ErrorMsg']))
        raise kopf.PermanentError('Lint failed')
    if (type(isInitialized) == tuple and not isInitialized[0]):
        logger.error("ERROR: The network {0} is not initialized".format(network))
        raise kopf.PermanentError('Lint failed')
    
    currentIP = getClientIP(Network=namespacedNetowrk,Client=name)

    core_v1_api = client.CoreV1Api()

    subnetReport = getNetworkReport(namespacedNetowrk)
    requestedIP = None

    Linter = False
    if (new != None):
        ip = new
        subnetInfo = get_all_entries(database_name=namespacedNetowrk,table_name='subnet')
        if(type(subnetInfo) == dict and 'ErrorMsg' in subnetInfo):
            logger.error(subnetInfo['ErrorMsg'])
            raise kopf.PermanentError("Can't access database")

        subnetInfo = list(subnetInfo['Enteries'])[0]
    # Check IP is valid
        IPValid = isValidIP(IP=ip)
        if(type(IPValid) == dict and 'ErrorMsg' in IPValid):
            logger.error("The IP '{0}' is not valid IP Address".format(ip))
            Linter = True
        else:
            
            IPisInReservedRange = True
            IPisInReservedIPs = True
            # Check if IP is in Reserved Range
            if('reservedRange' in subnetInfo):
                reservedRange = subnetInfo['reservedRange'].split('-')
                ipInRange = isIPinRange(range=reservedRange,IP=ip)
                if (not ipInRange):
                    IPisInReservedRange = False

            # Check if IP is in Reserved IPs
            if('reservedIPs' in subnetInfo):
                reservedIPs = subnetInfo['reservedIPs'].split(',')
                if(ip not in reservedIPs):
                    IPisInReservedIPs = False

            if(not IPisInReservedIPs and not IPisInReservedRange):
                Linter = True
                logger.error("The IP '{0}' is not in the reserved range or reserved IPs".format(ip))
            

    if(Linter):
        raise kopf.PermanentError('Lint failed')
    
    if(old != None and new == None):
        
        if(subnetReport['NumFreeNonStaticIPs'] == 0):
            logger.error("ERROR: There is no enough non-static IP to assign")
            raise kopf.TemporaryError('No enough IP')
        
        returnResult = returnIP(Network=namespacedNetowrk,clientName=name)

        if(type(returnResult) == dict and 'ErrorMsg' in returnResult):
        
            logger.error(returnResult['ErrorMsg'])
            raise kopf.PermanentError("can't release IP")
    
        if(returnResult != True):
            raise kopf.PermanentError("Can't release IP")

        requestedIP = requestIP(
        Network=namespacedNetowrk,
        clientName=name,
        IP=None
    )
    
        if(type(requestedIP) == dict):

            logger.error("ERROR : {0}".format(requestedIP['ErrorMsg']))
            
            if(requestedIP['ErrorCode'] == '805'):
                raise kopf.TemporaryError("Can't request IP for client")
            
            raise kopf.PermanentError("Can't request IP for client")

    if (new != None):

        if (isIPLeased(IP=new,Network=namespacedNetowrk)):

            logger.error("ERROR: the requested IP '{0}' is already leased".format(new))
            raise kopf.TemporaryError("Can't assign requested IP")
        
        returnResult = returnIP(Network=namespacedNetowrk,clientName=name)

        if(type(returnResult) == dict and 'ErrorMsg' in returnResult):
        
            logger.error(returnResult['ErrorMsg'])
            raise kopf.PermanentError("can't release IP")
    
        if(returnResult != True):
            raise kopf.PermanentError("Can't release IP")

        requestedIP = requestIP(
        Network=namespacedNetowrk,
        clientName=name,
        IP=new
    )
    
        if(type(requestedIP) == dict):

            logger.error("ERROR : {0}".format(requestedIP['ErrorMsg']))
            
            if(requestedIP['ErrorCode'] == '805'):
                raise kopf.TemporaryError("Can't request IP '{0}' for client".format(new))
            
            raise kopf.PermanentError("Can't request IP '{0}' for client".format(new))
    

    configMap_patch = {'data': {'IP': requestedIP }}

    try:
        core_v1_api.patch_namespaced_config_map(
            name="{0}.{1}".format(name,'tracerip'),
            namespace=namespace,
            body= configMap_patch
        )
    except ApiException as e:
        raise kopf.PermanentError("Can't access k8s API Server: %s\n" % e)

    logger.info("The client '{0}' IP is changed from '{1}' to '{2}'".format(name,currentIP,requestedIP))


    











    


# Network = 'Network1'
# CIDR = '192.168.0.0/24'
# NewCIDR = '192.168.0.0/23'

# result = makeSubnetLarger(Network=Network,NewCIDR=NewCIDR,OldCIDR=CIDR)

# result = removeNetwork(Network=Network)

# print(result)
# ReservedRange = '192.168.0.0-192.168.0.10'
# ReservedIPs = ['192.168.0.20','192.168.0.22']

# result = initializeSubnet(
#     Network=Network,
#     CIDR=CIDR,ReservedRange=ReservedRange,
#     ReservedIPs=ReservedIPs
# )
# print(result)
#result = requestIP(Network=Network,clientName='Client2')
#result = returnIP(SubnetName=SubnetName,clientName='Client1')
# result = getNetworkReport(Network=Network)
# print(result['NumFreeNonStaticIPs'])
# print(result['NumFreeStaticIPs'])
# print(result['NumLeasedNonStaticIPs'])

# result = isNetworkInitialized(Network=Network)
# print(result)