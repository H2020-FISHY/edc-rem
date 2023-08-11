import pika, json, sys, os, base64

class RMQproducer:
    def __init__(self, routingKey, config):

        self.config = config
        self.routingKey = routingKey
        self.exchange = self.config["exchange"]
        self.connection = self._create_connection()

    def _create_connection(self):

        credentials = pika.PlainCredentials(self.config['login'], self.config['password'])
        parameters = pika.ConnectionParameters(host=self.config['host'],
                        port=self.config['port'],
                        virtual_host='/',
                        credentials=credentials)
        #parameters = pika.ConnectionParameters("host.docker.internal")
        #parameters = pika.ConnectionParameters("127.0.0.1")
        connection = pika.BlockingConnection(parameters)
        return connection

    def send_message(self, message):

        channel = self.connection.channel()

        channel.exchange_declare(exchange=self.exchange, exchange_type='direct')

        channel.queue_declare(queue=self.routingKey)

        channel.basic_publish(exchange=self.exchange,
                            routing_key=self.routingKey,
                            body=json.dumps(message))

        channel.close()

        self.connection.close()

        print(" [x] Sent %r" % message)

key = "reportsedc"
notification_producer_config = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : "reportsedc",
                                'login':'tubs',
                                'password':'sbut'}

if __name__ == '__main__':

    try:

        message = {
            "id": "20ff6f22-9359-44ff-b0c9-6cf9d03cc6f3",
            "task_type": "reports.create.cef",
            "details": {
                "id": "3eb8218e-c1e6-498e-8f25-f06db371806a",
                "device_product": "XL-SIEM",
                "device_version": "1.0",
                "event_name": "Brute of service",
                "device_event_class_id": "Unknown",
                "severity": "5",
                "extensions_list": "{\"ts\": \"2023-07-20 16:10:23\", \"id\": \"c568d44dffa049db92604772d406bc40\", \"relEvents\": \"[270f11eeb6a90242ac1100024609f5da; 270f11eeb6a90242ac1100024690481a; 270f11eeb6a90242ac11000246fdab80; 270f11eeb6a90242ac11000258f694b4; 270f11eeb6a90242ac1100028cc91208]\", \"pluginId\": \"70000\", \"pluginName\": \"cyber-monitor\", \"pluginSid\": \"100103\", \"backlogId\": \"45ee50dd27e44dc189c6412a5684d45d\", \"src\": \"10.13.150.9\", \"spt\": \"0\", \"shost\": \"00000000\", \"smac\": \"UmVzcG9uc2UgY29kZTogNDAx\", \"suser\": \"TWFjaGluZTogc3J2cHQ1MjEgd2Rpc3A=\", \"dst\": \"0.0.0.0\", \"dpt\": \"0\", \"dhost\": \"00000000\", \"sidName\": \"RGVuaWFsIG9mIHNlcnZpY2U=\", \"risk\": \"10\", \"reliability\": \"10\", \"proto\": \"6\", \"description\": \"Denial of service\", \"userData1\": \"TWV0aG9kOiBHRVQ=\", \"userData2\": \"TmV0OiAxMC4xMw==\", \"userData3\": \"UmVxdWVzdDogSFRUUC8xLjE=\", \"userData4\": \"UmVzcG9uc2UgY29kZTogNDAx\", \"userData5\": \"U2l6ZTogOTU3OA==\", \"userData6\": \"TWFjaGluZTogc3J2cHQ1MjEgd2Rpc3A=\", \"userData7\": \"TWVzc2FnZTogc2FwL3dkaXNwL2FkbWluL3B1YmxpYy9kZWZhdWx0Lmh0bWw=\", \"userData9\": \"VXNlcjogLQ==\"}",
                "pilot": "WBP"
            }
        }

        init_rabbit = RMQproducer(key, notification_producer_config)
        #message = {"payload": "malware Zeus 10.1.0.10 22 12.12.12.12"}
        init_rabbit.send_message(message)

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
