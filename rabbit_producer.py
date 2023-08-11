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

# Doc: https://www.rabbitmq.com/tutorials/tutorial-five-python.html

#queueName = 'IROQueue'
routingKey = "reportsedc"
notification_producer_config = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : "reportsedc",
                                'login':'tubs',
                                'password':'sbut'}

# https://github.com/H2020-FISHY/IRO/blob/main/iro/sending.py

if __name__ == '__main__':

    try:

        init_rabbit = RMQproducer(routingKey, notification_producer_config)
        message = {"payload": "malware Zeus 10.1.0.10 22 12.12.12.12"}
        init_rabbit.send_message(message)

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
