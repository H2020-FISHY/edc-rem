import requests, json, base64


# url="https://" + "fishy.xlab.si/tar/api/mspl"

# headers = {'Content-Type': 'application/json'}

# message = {"source": "test", "data": json.dumps({"test": "test1", "test2": "test3"}), "status": "both", "timestamp": "2022-09-09T11:26:23.531Z"}

# raw_response = requests.post(url, headers=headers, data=json.dumps(message))
# response = json.loads(raw_response.text)
# policy_id_cr = response["id"]
# print(policy_id_cr)

url="https://" + "fishy.xlab.si/tar/api/reports/v2"

headers = {'Content-Type': 'application/json'}

# message = {"source": "test", "data": json.dumps(), "status": "both", "timestamp": "2022-09-09T11:26:23.531Z"}

message = {
            "id": "3eb8218e-c1e6-498e-8f25-f06db371806a",
            "device_product": "XL-SIEM",
            "device_version": "1.0",
            "event_name": "Unauthorized access to admin pages",
            "device_event_class_id": "Unknown",
            "severity": "5",
            "extensions_list": "{\"ts\": \"2023-07-20 16:10:23\", \"id\": \"c568d44dffa049db92604772d406bc40\", \"relEvents\": \"[270f11eeb6a90242ac1100024609f5da; 270f11eeb6a90242ac1100024690481a; 270f11eeb6a90242ac11000246fdab80; 270f11eeb6a90242ac11000258f694b4; 270f11eeb6a90242ac1100028cc91208]\", \"pluginId\": \"70000\", \"pluginName\": \"cyber-monitor\", \"pluginSid\": \"100103\", \"backlogId\": \"45ee50dd27e44dc189c6412a5684d45d\", \"src\": \"10.13.150.9\", \"spt\": \"0\", \"shost\": \"00000000\", \"smac\": \"UmVzcG9uc2UgY29kZTogNDAx\", \"suser\": \"TWFjaGluZTogc3J2cHQ1MjEgd2Rpc3A=\", \"dst\": \"0.0.0.0\", \"dpt\": \"0\", \"dhost\": \"00000000\", \"sidName\": \"RGVuaWFsIG9mIHNlcnZpY2U=\", \"risk\": \"10\", \"reliability\": \"10\", \"proto\": \"6\", \"description\": \"Denial of service\", \"userData1\": \"TWV0aG9kOiBHRVQ=\", \"userData2\": \"TmV0OiAxMC4xMw==\", \"userData3\": \"UmVxdWVzdDogSFRUUC8xLjE=\", \"userData4\": \"UmVzcG9uc2UgY29kZTogNDAx\", \"userData5\": \"U2l6ZTogOTU3OA==\", \"userData6\": \"TWFjaGluZTogc3J2cHQ1MjEgd2Rpc3A=\", \"userData7\": \"TWVzc2FnZTogc2FwL3dkaXNwL2FkbWluL3B1YmxpYy9kZWZhdWx0Lmh0bWw=\", \"userData9\": \"VXNlcjogLQ==\"}",
            "pilot": "WBP"
        }

raw_response = requests.post(url, headers=headers, data=json.dumps(message))
response = json.loads(raw_response.text)


if raw_response.status_code == 201:
    response_data = raw_response.json()
    print(response_data)
else:
    print("Error:", raw_response.status_code)