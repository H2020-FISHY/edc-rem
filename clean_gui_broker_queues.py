import pika, sys, os
import json

class RMQsubscriber:

    def __init__(self, queueName, bindingKey, config):

        self.queueName = queueName
        self.bindingKey = bindingKey
        self.config = config
        self.exchange = self.config["exchange"]
        self.connection = self._create_connection()

    def __del__(self):
        if self.connection.is_open:
            self.connection.close()

    def _create_connection(self):

        credentials = pika.PlainCredentials(self.config['login'], self.config['password'])
        parameters = pika.ConnectionParameters(host=self.config['host'],
                          port=self.config['port'],
                          virtual_host='/',
                          credentials=credentials)
        #parameters = pika.ConnectionParameters("127.0.0.1")
        connection = pika.BlockingConnection(parameters)

        return connection

    def on_message_callback(self, channel, method, properties, body):

        print(" [x] Received %r" % body)
        info = json.loads(body.decode('utf-8'))
        print(info)
        print(json.dumps(info, indent=1))

    def setup(self):

        channel = self.connection.channel()

        channel.exchange_declare(exchange=self.exchange, exchange_type='direct')

        # This method creates or checks a queue
        channel.queue_declare(queue=self.queueName)

        # Binds the queue to the specified exchange
        channel.queue_bind(queue=self.queueName,
                        exchange=self.config['exchange'],
                        routing_key=self.bindingKey)

        channel.basic_consume(queue=self.queueName,
                            on_message_callback=self.on_message_callback,
                            auto_ack=True)

        print('[*] Waiting for data for ' + self.queueName + '. To exit press CTRL+C')

        try:

            channel.start_consuming()

        except KeyboardInterrupt:

            channel.stop_consuming()


queueName1 = 'edc_remediation_proposals'
key1 = "edc_remediation_proposals"
notification_consumer_config1 = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : "edc_remediationsedcpoli_proposals",
                                'login':'tubs',
                                'password':'sbut'}
queueName2 = 'edc_remediation_selection'
key2 = 'edc_remediation_selection'
notification_consumer_config2 = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : 'edc_remediationsedcpoli_selection',
                                'login':'tubs',
                                'password':'sbut'}

if __name__ == '__main__':

    try:

        switch = 0

        if switch == 1:
            init_rabbit = RMQsubscriber(queueName1, key1, notification_consumer_config1)
        else:
            init_rabbit = RMQsubscriber(queueName2, key2, notification_consumer_config2)

        init_rabbit.setup()

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)