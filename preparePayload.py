#!/usr/bin/env python3

import json
import os
import sys
import hvac
import requests
import configparser
import time
import openapi_spec_validator
import openapi_spec_validator.readers
import re
import base64
from requests.auth import HTTPBasicAuth


def checkIfAPIexists(config_dict):
    payload = {
        "types": [ "api" ],
        "scope": [
            {
                "attributeName": "apiName",
                "keyword": config_dict['api_name']
            },{
                "attributeName": "apiVersion",
                "keyword": config_dict['api_version']
            }
        ],
        "condition" : "and",
        "responseFields": [ "id", "apiName", "apiVersion" ]
        }
    
    postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/search", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    api_array = postresponse.json().get('api', [])
    if api_array:
        api_id = api_array[0].get('id')
        print("API gefunden: {}".format(api_id))
        return api_id
    else:
        print("API nicht gefunden")
        return False

def checkIfEndpointAliasExists(config_dict):
    payload = {
            "types": [ "alias" ],
            "scope": [
                {
                    "attributeName": "name",
                    "keyword": ".*EndpointAlias_" + config_dict['api_name'] + "_" + config_dict['api_version'] + ".*"
                }
            ],
            "responseFields": [ "id", "name", "type" ]
        }
    postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/search", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    if postresponse.ok:
        for alias in postresponse.json()["alias"]:
            if alias["name"] == "EndpointAlias_" + config_dict['api_name'] + "_" + config_dict['api_version']:
                print("EndpointAlias gefunden: {}".format(alias["id"]))
                return alias["id"]
    print("EndpointAlias nicht gefunden.")
    return False

def checkIfSecureAliasExists(config_dict):
    payload = {
            "types": [ "alias" ],
            "scope": [
                {
                    "attributeName": "name",
                    "keyword": ".*SecureAlias_" + config_dict['api_name'] + "_" + config_dict['api_version'] + ".*"
                }
            ],
            "responseFields": [ "id", "name", "type" ]
        }
    postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/search", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    if postresponse.ok:
        for alias in postresponse.json()["alias"]:
            if alias["name"] == "SecureAlias_" + config_dict['api_name'] + "_" + config_dict['api_version']:
                print("SecureAlias gefunden: {}".format(alias["id"]))
                return True
    print("SecureAlias nicht gefunden.")
    return False

def createEndpointAlias(config_dict, overwrite):
    payload = { 
        "endPointURI": config_dict["backend_url"],
        "connectionTimeout": "30",
        "optimizationTechnique": "None",
        "readTimeout": "30",
        "passSecurityHeaders": None,
        "keystoreAlias": "",
        "keyAlias": None,
        "truststoreAlias":"",
        "stage":"",
        "name": "EndpointAlias_" + config_dict['api_name']+ "_" + config_dict['api_version'],
        "description": None,
        "type":"endpoint"
        }
    
    if overwrite != False:
        payload["id"] = overwrite
        postresponse = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/alias/" + overwrite, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/alias", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    return postresponse

def createSecureAlias(config_dict, overwrite):
    client = hvac.Client(
        url=os.environ['bamboo_VaultURL'],
        verify=False
    )

    client.auth.approle.login(
        role_id=os.environ['bamboo_RoleID'],
        secret_id=os.environ['bamboo_SecretID']
    )

    read_response = client.read(path=config_dict["vault_path"])
    basicAuthCreds = read_response['data']['data']

    payload = { 
        "authType": "HTTP_BASIC",
        "stage": "",
        "httpAuthCredentials": { 
            "domain": "",
             "userName": basicAuthCreds[config_dict["username_variable"]],
              "password": base64.b64encode(basicAuthCreds[config_dict["password_variable"]].encode("utf-8")) 
        },
        "authMode": "NEW",
        "name": "SecureAlias_" + config_dict['api_name'] + "_" + config_dict['api_version'],
        "description": None,
        "type":"httpTransportSecurityAlias"
    }

    if overwrite != False:
        payload["id"] = overwrite
        postresponse = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/alias/" + overwrite, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/alias", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    return postresponse

def getCorrectEnforcementIDandOrder(config_dict, PolicyID, stageKey, templateKey):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    id = 0
    for enforcement in PolicyDetails["policy"]["policyEnforcements"]:
        if enforcement["stageKey"] == stageKey:
            for enforcementObject in enforcement["enforcements"]:
                EnforcementType = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + enforcementObject["enforcementObjectId"] , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)["policyAction"]["templateKey"]
                if EnforcementType == templateKey:
                    return enforcementObject["enforcementObjectId"], enforcementObject["order"]
                else:
                    if enforcementObject["order"] >= id:
                        id = enforcementObject["order"] + 1
    return None, id

def setEndpoint(config_dict, PolicyID):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Straight Through Routing", "locale": "en" } ], 
                "templateKey": "straightThroughRouting",
                "parameters": [
                    { "templateKey": "endpointUri", "values": [ "${EndpointAlias_"+ config_dict["api_name"] + "_" + config_dict['api_version'] + "}/${sys:resource_path}" ] },
                    { "templateKey": "method", "values": [ "CUSTOM" ] }
                ], "active": False
            }
        }
    
    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "routing", "straightThroughRouting")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "routing" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp

def setBasicAuthPassthrough(config_dict, PolicyID):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Outbound Auth - Transport", "locale": "en" } ], 
                "templateKey": "outboundTransportAuthentication",
                "parameters": [
                    { "templateKey": "transportSecurity", "parameters": [
                            { "templateKey": "authType", "values": [ "HTTP_BASIC" ] }, 
                            { "templateKey": "authMode", "values": [ "INCOMING_HTTP_BASIC_AUTH" ] } ] } 
                ], "active": False
            }
        }
    

    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "routing", "outboundTransportAuthentication")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "routing" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp

def setBasicAuthtoBackend(config_dict, PolicyID):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Outbound Auth - Transport", "locale": "en" } ], 
                "templateKey": "outboundTransportAuthentication",
                "parameters": [
                    { "templateKey": "transportSecurity", "parameters": [
                            { "templateKey": "authType", "values": [ "alias" ] }, 
                            { "templateKey": "authMode", "values": [ "NEW" ] } ] } ,
                            { "templateKey": "alias", "values": [ "${SecureAlias_" + config_dict["api_name"] + "}" ] } 
                ], "active": False
            }
        }
    
    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "routing", "outboundTransportAuthentication")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "routing" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp


def setClientBasicAuth(config_dict, PolicyID):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Identify & Authorize", "locale": "en" } ], 
                "templateKey": "evaluatePolicy",
                "parameters": [
                    { "templateKey": "logicalConnector", "values": [ "OR" ] },
                    { "templateKey": "allowAnonymous", "values": [ "false" ] },
                    { "templateKey": "triggerPolicyViolationOnMissingAuthorizationHeader", "values": [ "false" ] },
                    { "templateKey": "IdentificationRule", "parameters": [
                            { "templateKey": "applicationLookup", "values": [ "strict" ] }, 
                            { "templateKey": "identificationType", "values": [ "httpBasicAuth" ] } ] } 
                ], "active": False
            }
        }

    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "IAM", "evaluatePolicy")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "IAM" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp


def setClientAPIKey(config_dict, PolicyID):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Identify & Authorize", "locale": "en" } ], 
                "templateKey": "evaluatePolicy",
                "parameters": [
                    { "templateKey": "logicalConnector", "values": [ "OR" ] },
                    { "templateKey": "allowAnonymous", "values": [ "false" ] },
                    { "templateKey": "triggerPolicyViolationOnMissingAuthorizationHeader", "values": [ "false" ] },
                    { "templateKey": "IdentificationRule", "parameters": [
                            { "templateKey": "applicationLookup", "values": [ "strict" ] }, 
                            { "templateKey": "identificationType", "values": [ "apiKey" ] } ] } 
                ], "active": False
            }
        }
    
    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "IAM", "evaluatePolicy")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "IAM" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp

def createOAuth2Scope(config_dict):
    # Abrufen des JSON von der ersten URL
    response = requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/alias/local" , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"})

    if response.ok:
        # JSON-Daten aus der Antwort extrahieren
        json_data = response.json()

        # Hinzufügen des neuen Scopes
        new_scope = {
            "name": config_dict["api_name"] + "_" + config_dict['api_version'] +  "_Scope",
            "description": "Scope for " + config_dict["api_name"] + "_" + config_dict['api_version']
        }
        json_data["alias"]["scopes"].append(new_scope)

        # Senden Sie das aktualisierte JSON an die zweite URL mit einer PUT-Anfrage
        put_response = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/alias/local", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"} , data=json.dumps(json_data["alias"]))
        if put_response.ok:
            print("Auth Sever Konfiguration erfolgreich aktualisiert.")
        else:
            print("Fehler beim Aktualisieren der Auth Sever Konfiguration. Statuscode:", put_response.status_code)
    else:
        print("Fehler beim Abrufen der Auth Sever Konfiguration. Statuscode:", response.status_code)
    return

def createOAuth2ScopeMapping(config_dict, api_id):
    payload = {
        "types": ["GATEWAY_SCOPE"],
        "responseFields": ["id", "scopeName", "scopeDescription", "audience", "apiScopes", "requiredAuthScopes"],
        "from": 0,
        "size": 20,
        "sortByField": "scopeName",
        "sortOrder": "ASC"
    }
    postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/search", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))

    if postresponse.ok:
        scopes_data = postresponse.json()
        for scope in scopes_data.get("gateway_scope", []):
            if api_id in scope.get("apiScopes", []):
                return True

    payload = {
        "types": ["alias"],
        "scope": [
            {
                "attributeName": "type",
                "keyword": "authServerAlias"
            }
        ],
        "responseFields": ["id", "name", "type", "description", "scopes"],
        "condition": "or",
        "sortByField": "name"
    }

    postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/search", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))

    if postresponse.ok:
        authServerData = postresponse.json()
        scope_found = False
        for alias in authServerData["alias"]:
            if "scopes" in alias:
                for scope in alias["scopes"]:
                    if "name" in scope and scope["name"] == config_dict["api_name"] + "_" + config_dict['api_version'] + "_Scope":
                        scope_found = True
                        break
    if not scope_found:
        createOAuth2Scope(config_dict)
    
    payload = { "apiScopes": [ api_id ],
        "requiredAuthScopes": [
            {
                "authServerAlias": "local",
                "scopeName": config_dict["api_name"] + "_" + config_dict['api_version'] + "_Scope"
            }
        ],
        "scopeName": "local:"+config_dict["api_name"] + "_" + config_dict['api_version'] + "_Scope",
        "scopeDescription": "Mapping for " + config_dict["api_name"] + "_" + config_dict['api_version'] + "_Scope",
        "audience": ""
    }

    postresponse = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/scopes", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    if postresponse.ok:
        return True
    else:
        raise Exception('601', 'Scope Mapping konnte nicht angelegt werden.')

def setClientOAuth2(config_dict, PolicyID):
    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Identify & Authorize", "locale": "en" } ], 
                "templateKey": "evaluatePolicy",
                "parameters": [
                    { "templateKey": "logicalConnector", "values": [ "OR" ] },
                    { "templateKey": "allowAnonymous", "values": [ "false" ] },
                    { "templateKey": "triggerPolicyViolationOnMissingAuthorizationHeader", "values": [ "false" ] },
                    { "templateKey": "IdentificationRule", "parameters": [
                            { "templateKey": "applicationLookup", "values": [ "strict" ] }, 
                            { "templateKey": "identificationType", "values": [ "oAuth2Token" ] } ] } 
                ], "active": False
            }
        }


    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "IAM", "evaluatePolicy")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "IAM" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp

def setLoggingOptions(config_dict, PolicyID, logLevel):
    reqHeaders = False
    reqPayload = False
    respHeader = False
    respPayload = False
    if logLevel == "Extended":
        reqHeaders = True
        reqPayload = True
    elif logLevel == "Full":
        reqHeaders = True
        reqPayload = True
        respHeader = True
        respPayload = True

    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)

    payload = { "policyAction": {
        "names": [ { "value": "Log Invocation", "locale": "en" } ], 
                "templateKey": "logInvocation",
                "parameters": [
                    { "templateKey": "storeRequestHeaders", "values": [ reqHeaders ] },
                    { "templateKey": "storeRequestPayload", "values": [ reqPayload ] },
                    { "templateKey": "storeResponseHeaders", "values": [ respHeader ] },
                    { "templateKey": "storeResponsePayload", "values": [ respPayload ] },
                    { "templateKey": "storeAsZip", "values": [ "false" ] },
                    { "templateKey": "logGenerationFrequency", "values": [ "Always" ] },
                    { "templateKey": "destination", "parameters": [
                            { "templateKey": "destinationType", "values": [ "GATEWAY" ] }] },
                    { "templateKey": "destination", "parameters": [
                            { "templateKey": "destinationType", "values": [ "APIPORTAL" ] }] }
                ], "active": False
            }
        }

    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "LMT", "logInvocation")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "LMT" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp


def setProtocol(config_dict, PolicyID):
    if config_dict["protocol"] == "BOTH":
        protocols = ["http", "https"]
    else:
        protocols = [ config_dict["protocol"].lower() ]

    PolicyDetails = json.loads(requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID , auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}).text)
    payload = { "policyAction": {
        "names": [ { "value": "Enable HTTP / HTTPS", "locale": "en" } ], 
                "templateKey": "entryProtocolPolicy",
                "parameters": [
                    { "templateKey": "protocol", "values": protocols }
                ], "active": False
            }
        }

    EnforcementID, Order = getCorrectEnforcementIDandOrder(config_dict, PolicyID, "transport", "entryProtocolPolicy")
    if EnforcementID != None:
       puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions/" + EnforcementID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
    else:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policyActions", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(payload))
        PolActionResp = json.loads(resp.text)
        PolicyDetails["policy"]["policyEnforcements"].append({ "enforcements": [ { "enforcementObjectId": PolActionResp["policyAction"]["id"], "order": Order } ], "stageKey": "transport" })
        puttingresp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/policies/" + PolicyID, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json", "Content-Type": "application/json"}, data=json.dumps(PolicyDetails))
    return puttingresp


def checkRegulations(config_dict):
    absicherung = ""
    SecurityOrder = {
        0: "NoAuth",
        1: "APIKey",
        2: "BasicAuth",
        3: "OAuth2"
    }

    # Ermittle die Sicherheitsstufe der erwarteten Methode
    expected_security_level = SecurityOrder.get(config_dict["sicherheitsstufe"], None)

    # Ermittle die Sicherheitsstufe der aktuellen Methode
    current_security_level = [key for key, value in SecurityOrder.items() if value == config_dict["absicherung"]][0]

    # Wenn die aktuelle Methode niedriger in der Reihenfolge ist,
    # hebe sie auf die erwartete Methode an.
    if current_security_level < config_dict["sicherheitsstufe"]:
        print("Absicherung wird von {} auf {} angehoben, da die gewählte Absicherung nicht den Vorgaben entspricht".format(config_dict["absicherung"], expected_security_level))
        absicherung = expected_security_level
    else:
        absicherung = config_dict["absicherung"]

    logginglevel = ""
    if config_dict["sicherheitsstufe"] > 1 and config_dict["logging_options"] == "Minimal":
        print("Logging wird von {} auf {} angehoben, da das gewählte Logging nicht den Vorgaben entspricht".format(config_dict["logging_options"], "Extended"))
        logginglevel = "Extended"
    else:
        logginglevel = config_dict["logging_options"]

    return absicherung, logginglevel


def readConfig():
    config = configparser.ConfigParser()
    config.read(os.environ['bamboo_APIConfigFile'])

    api_specfile_name = config['API']['API_Specfile_Name']
    api_name = config['API']['API_Name']
    api_version = config['API']['API_Version']
    description = config['API']['Description']
    protocol = config['API']['Protocol']
    sicherheitsstufe = int(config['API']['Sicherheitsstufe'])
    absicherung = config['API']['Absicherung']
    backend_url = config['API']['BackendURL']
    logging_options = config['API']['Logging_Options']
    overwrite_if_exists = config['API'].getboolean('Overwrite_IfExists')
    portal_gruppen = config['API']['Portal_Gruppen'].split(',')
    outbound_auth = config['API']['Outbound_Auth']

    if outbound_auth == "BasicAuth":
        vault_path = config['Auth']['Vault_Path']
        username_variable = config['Auth']['Username_Variable']
        password_variable = config['Auth']['Password_Variable']

    # Authentication
    client = hvac.Client(
        url=os.environ['bamboo_VaultURL'],
        verify=False
    )

    client.auth.approle.login(
        role_id=os.environ['bamboo_RoleID'],
        secret_id=os.environ['bamboo_SecretID']
    )

    read_response = client.read(path=os.environ['bamboo_VaultPathAGWCreds'])
    apiGWCreds = read_response['data']['data']
    basic = requests.auth.HTTPBasicAuth(apiGWCreds["username"], apiGWCreds["password"])
    return {
        'api_specfile_name': api_specfile_name,
        'api_name': api_name,
        'api_version': api_version,
        'description': description,
        'protocol': protocol,
        'sicherheitsstufe': sicherheitsstufe,
        'absicherung': absicherung,
        'backend_url': backend_url,
        'logging_options': logging_options,
        'overwrite_if_exists': overwrite_if_exists,
        'portal_gruppen': portal_gruppen,
        'outbound_auth': outbound_auth,
        'vault_path': vault_path if outbound_auth == "BasicAuth" else None,
        'username_variable': username_variable if outbound_auth == "BasicAuth" else None,
        'password_variable': password_variable if outbound_auth == "BasicAuth" else None,
        'apiGWCreds': basic
    }

def validateConfig(config_dict):
    errors = []

    # Überprüfe, ob alle erforderlichen Felder vorhanden sind
    required_fields = [
        'api_specfile_name',
        'api_name',
        'api_version',
        'protocol',
        'sicherheitsstufe',
        'absicherung',
        'backend_url',
        'logging_options',
        'overwrite_if_exists',
        'portal_gruppen',
        'outbound_auth'
    ]
    for field in required_fields:
        if field not in config_dict:
            errors.append(f"Fehlendes Feld: {field}")
    
    # Überprüfe das Format von API_Name, falls vorhanden
    if 'api_name' in config_dict:
        api_name_pattern = r'^[a-zA-Z0-9,_-]+$'
        if not re.match(api_name_pattern, config_dict['api_name']):
            errors.append("Ungültiges Format für API_Name")

    # Überprüfe das Format von API_Version, falls vorhanden
    if 'api_version' in config_dict:
        api_version_pattern = r'^\d+\.\d+$'
        if not re.match(api_version_pattern, config_dict['api_version']):
            errors.append("Ungültiges Format für API_Version")

    # Überprüfe das Format von Protcol
    valid_protocol_options = ['HTTP', 'HTTPS', 'BOTH']
    if config_dict['protocol'] not in valid_protocol_options:
        errors.append("Ungültiger Wert für Protocol")

    # Überprüfe das Format von Sicherheitsstufe
    if config_dict['sicherheitsstufe'] not in range(4):
        errors.append("Ungültiges Format für Sicherheitsstufe")

    # Überprüfe das Format von Absicherung
    valid_absicherung = ['NoAuth', 'BasicAuth', 'APIKey', 'OAuth2']
    if config_dict['absicherung'] not in valid_absicherung:
        errors.append("Ungültige Absicherung")
    
    # Überprüfe das Format von BackendURL
    backend_url = config_dict['backend_url']
    url_pattern = r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d{2,5})?(\/\S*)?$'
    if not re.match(url_pattern, backend_url):
        errors.append("Ungültiges Format für BackendURL")

    # Überprüfe das Format von Logging_Options
    valid_logging_options = ['Minimal', 'Extended', 'Full']
    if config_dict['logging_options'] not in valid_logging_options:
        errors.append("Ungültiger Wert für Logging_Options")

    # Überprüfe das Format von Overwrite_IfExists
    if config_dict['overwrite_if_exists'] not in [True, False]:
        errors.append("Ungültiger Wert für Overwrite_IfExists")

    # Überprüfe das Format von Portal_Gruppen
    if not config_dict['portal_gruppen']:
        errors.append("Portal_Gruppen darf nicht leer sein")

    # Überprüfe das Format von outbound_auth
    valid_outbound_auth = ['False', 'BasicAuthPassthrough', 'BasicAuth']
    if config_dict['outbound_auth'] not in valid_outbound_auth:
        errors.append("Ungültiger Wert für Outbound_Auth")

    # Überprüfe Vault-spezifische Felder, falls outbound_auth = BasicAuth
    if config_dict['outbound_auth'] == 'BasicAuth':
        required_vault_fields = ['vault_path', 'username_variable', 'password_variable']
        for field in required_vault_fields:
            if field not in config_dict:
                errors.append(f"Fehlendes Feld für BasicAuth: {field}")
    
    # Wenn Fehler gefunden wurden, gib sie aus
    if errors:
        for error in errors:
            print(error)
        raise Exception('602', "Error in Konfigurationsparameter. Abbruch.")

    # Wenn alle Überprüfungen erfolgreich waren, gib True zurück
    return True

def prepareConfig(config_dict):
    spec_dict, base_uri = openapi_spec_validator.readers.read_from_filename("./API/" + config_dict["api_specfile_name"])
    if config_dict["api_name"] == "":
        config_dict["api_name"] = spec_dict["info"]["title"]
    if config_dict["api_version"] == "":
        config_dict["api_version"] = spec_dict["info"]["version"]
    if config_dict["description"] == "":
        config_dict["description"] = spec_dict["info"]["description"]
    return

def readOpenAPIFile(config_dict):
    spec_dict, base_uri = openapi_spec_validator.readers.read_from_filename("./API/" + config_dict["api_specfile_name"])
    if spec_dict["openapi"] and not (spec_dict["openapi"].startswith("3.0") or spec_dict["openapi"].startswith("3.1")):
            raise Exception('600', "Nur OpenAPI 3.0 oder 3.1 File´unterstützt. Abbruch.")
    try:
        openapi_spec_validator.validate_spec(spec_dict)
        return True
    except:
        print("OpenAPI Specfile enthält folgende Fehler:")
        if spec_dict["openapi"].startswith("3.0"):
            errors_iterator = openapi_spec_validator.openapi_v30_spec_validator.iter_errors(spec_dict)
        elif spec_dict["openapi"].startswith("3.1"):
            errors_iterator = openapi_spec_validator.openapi_v31_spec_validator.iter_errors(spec_dict)
        for error in errors_iterator:
            print(error)
        raise Exception('603', "Abbruch aufgrund Specfile Fehler!")

def deployAPI(config_dict):
    # Check if API exists
    apicheck = checkIfAPIexists(config_dict)
        
    apispecpayload = {
        'file': ('API.json', open("./API/" + config_dict["api_specfile_name"], 'rb')),
        'type': (None, 'openapi'),
        'apiVersion': (None, config_dict["api_version"]),
        "apiName": (None, config_dict["api_name"]),
        "apiDescription": (None, config_dict["description"]),
        "teams": (None,None)
    }
    if not apicheck:
        resp = requests.post(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/apis", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}, files=apispecpayload)
    elif apicheck != False and config_dict["overwrite_if_exists"]:
        deactivateAPI(config_dict, apicheck)
        apispecpayload['apiId'] = apicheck
        resp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/apis/" + apicheck, auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"}, files=apispecpayload)
    else:
        raise Exception('604', "API existiert bereits und darf nicht überschrieben werden! Abbruch")

    APICreationResp = json.loads(resp.text)
    if resp.ok:
        API_ID = APICreationResp["apiResponse"]["api"]["id"]
        PolicyID = APICreationResp["apiResponse"]["api"]["policies"][0]
        return API_ID, PolicyID
    else:
        #400 - Bad Request if already exists
        print("Deployment fehlgeschlagen! Errorcode: {}".format(resp.status_code))
        print(resp.reason)
        print(resp.text)
        raise Exception('605', "API Deployment fehlgeschlagen! API Gateway Error Abbruch")

def setPolicies(config_dict, PolicyID):
    absicherung, loggingLevel = checkRegulations(config_dict)
    # EndpunktAlias erstellen
    createEndpointAlias(config_dict, checkIfEndpointAliasExists(config_dict))
    setEndpoint(config_dict, PolicyID)
    setProtocol(config_dict, PolicyID)
    # Wenn notwendig SecuAlias Erstellen
    if config_dict["outbound_auth"] == "BasicAuth":
        createSecureAlias(config_dict, checkIfSecureAliasExists(config_dict))
        setBasicAuthtoBackend(config_dict, PolicyID)
    elif config_dict["outbound_auth"] == "BasicAuthPassthrough":
        setBasicAuthPassthrough(config_dict, PolicyID)
    # Absicherung Setzen
    if absicherung == "BasicAuth":
        setClientBasicAuth(config_dict, PolicyID)
    elif absicherung == "APIKey":
        setClientAPIKey(config_dict, PolicyID)
    elif absicherung == "OAuth2":
        createOAuth2ScopeMapping(config_dict, checkIfAPIexists(config_dict))
        setClientOAuth2(config_dict, PolicyID)
    # Logging setzen
    setLoggingOptions(config_dict, PolicyID, loggingLevel)
    return True

def activateAPI(config_dict, api_id):
    resp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/apis/" + api_id + "/activate", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"})

    if resp.ok:
        print("API erfolgreich aktiviert")
        return True
    elif resp.status_code == 400:
        print("Failed to activate API. API is already in an activated state or no operations/resources are present or none are enabled.")
        #Should never have activated at this point - only happens when no methods are present
        raise Exception('606', "Failed to activate API")
    elif resp.status_code == 401:
        print("Failed to activate API. User doesn't have the required privileges or provided credentials are incorrect.")
        raise Exception('606', "Failed to activate API")
    elif resp.status_code == 404:
        print("Failed to activate API. The specified apiId was not found in the API Gateway.")
        raise Exception('606', "Failed to activate API")
    else:
        print(f"Failed to activate API. Status code: {resp.status_code}")
        raise Exception('606', "Failed to activate API")

def deactivateAPI(config_dict, api_id):
    resp = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/apis/" + api_id + "/deactivate", auth=config_dict["apiGWCreds"], headers={"Accept":"application/json"})

    if resp.ok:
        print("API erfolgreich deaktiviert")
        return True
    elif resp.status_code == 400:
        print("API ist bereits deaktiviert.")
        # This can happen when last deployment was bad. Dont raise Exception!
        return False
    elif resp.status_code == 401:
        print("Deaktivieren der API fehlgeschlagen! Userrechte nicht aussreichen oder Login fehlgeschlagen")
        raise Exception('607', "Deaktivieren der API fehlgeschlagen!")
    elif resp.status_code == 404:
        print("Deaktivieren der API fehlgeschlagen! API ID konnte nicht gefunden werden")
        raise Exception('607', "Deaktivieren der API fehlgeschlagen!")
    else:
        print(f"Failed to deactivate API. Status code: {resp.status_code}")
        raise Exception('607', "Deaktivieren der API fehlgeschlagen!")


def exportAPIandSaveToGit(config_dict, API_ID, repository_path):
    response = requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/archive?apis=" + API_ID + "&include-documents=true", auth=config_dict["apiGWCreds"])
    
    if response.ok:
        with open(repository_path + config_dict["api_name"] + "_" + config_dict["api_version"] + ".zip", 'wb') as file:
            file.write(response.content)
        commit_message = "Adding Backup File of " + config_dict["api_name"] + "_" + config_dict["api_version"]
        with open('Commit.txt', 'w') as f:
            f.write('backup_CommitMessage=' + commit_message)
        print("Backup File erfolgreich heruntergeladen.")
    else:
        print(f"Download des Backupfiles fehlgeschlagen. Status code: {response.status_code}")
        raise Exception('608', "Backup konnte nicht erstellt werden. Deployment wird als fehlgeschlagen erachtet!")


def publishAPI(config_dict, api_id):
    # Fetch Portal Gateway ID
    response = requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/portalGateways", auth=config_dict["apiGWCreds"], headers={"Accept": "application/json"})
    if response.status_code != 200:
        raise Exception('609', "API Portal ID konnte nicht ermittelt werden.")

    portal_gateways = response.json().get("portalGatewayResponse", [])
    if not portal_gateways:
        print("No portal gateways found.")
        raise Exception('609', "API Portal ID konnte nicht ermittelt werden.")

    portal_gateway_id = portal_gateways[0].get("id")
    if not portal_gateway_id:
        print("Failed to extract portal gateway ID.")
        raise Exception('609', "API Portal ID konnte nicht ermittelt werden.")

    # Publish API for all communities
    community_ids = []
    for community_name in config_dict["portal_gruppen"]:
        response = requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/portalGateways/communities?portalGatewayId=" + portal_gateway_id, auth=config_dict["apiGWCreds"], headers={"Accept": "application/json"})
        if response.status_code != 200:
            raise Exception('610', "API Portal communities konnten nicht abgerufen werden.")

        communities = response.json().get("portalGatewayResponse", {}).get("communities", {}).get("portalCommunities", [])
        if not communities:
            raise Exception('610', "API Portal communities konnten nicht abgerufen werden.")

        community = next((c for c in communities if c.get("name") == community_name), None)
        if not community:
            raise Exception('611', "Gewählte API Portal community wurde nicht gefunden.")

        community_id = community.get("id")
        if not community_id:
            raise Exception('612', "Gewählte API Portal community ID konnte nicht ermittelt werden.")

        community_ids.append(community_id)


    resp = requests.get(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/apis/" + api_id, auth=config_dict["apiGWCreds"], headers={"Accept": "application/json"})
    if resp.ok:
        default_endpoints = resp.json().get("apiResponse", {}).get("gatewayEndPoints", [])
    else:
        raise Exception('614', "API Endpunkte konnten ermittelt werden.")

    publish_api_payload = {
        "communities": [community_ids],
        "endpoints": default_endpoints,
        "pubSOAPMethods": ""
    }

    response = requests.put(os.environ['bamboo_APIGatewaysBaseURL'] + "/rest/apigateway/apis/" + api_id + "/publish?portalGatewayId=" + portal_gateway_id, json=publish_api_payload, auth=config_dict["apiGWCreds"], headers={"Accept": "application/json"})

    if response.ok:
        print("API erfolgreich veröffentlicht.")
        return True
    else:
        raise Exception('613', "API konnte am API Portal nicht veröffentlicht werden.")


def __main__():
    repository_path = './Backup/'
    try:
        config_dict = readConfig()
        readOpenAPIFile(config_dict)
        prepareConfig(config_dict)
        validateConfig(config_dict)
        API_ID, PolicyID = deployAPI(config_dict)
        time.sleep(3) # Warten, da sonst ID noch nicht komplett im System repliziert ist. Aktivieren und Publish funktioniert sonst nicht
        setPolicies(config_dict, PolicyID)
        exportAPIandSaveToGit(config_dict, API_ID, repository_path)
        activateAPI(config_dict, API_ID)
        publishAPI(config_dict, API_ID)
    except Exception as exc:
        # Deavtivate API IF ANY STEP FAILED !
        exccode, exctext = exc.args
        print("Fehler " + str(exccode) + " aufgetreten. " + exctext)
        # Aussnahme API wurde nicht deployed weil überschreiben deaktiviert ist.
        if int(exccode) != 604:
            if not API_ID:
                API_ID = checkIfAPIexists(config_dict)
            if API_ID: 
                deactivateAPI(config_dict, API_ID)
        exit(exccode)


__main__()