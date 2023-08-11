import pika, sys, os
import json

class RMQsubscriberCR:

    def __init__(self, queueName, bindingKey, config, callback):

        self.queueName = queueName
        self.bindingKey = bindingKey
        self.config = config
        self.exchange = self.config["exchange"]
        self.connection = self._create_connection()
        self.callback = callback

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

    def setup(self):

        channel = self.connection.channel()

        channel.exchange_declare(exchange=self.exchange, exchange_type='topic') # topic (Prod) direct (Testing)

        # This method creates or checks a queue
        channel.queue_declare(queue=self.queueName)

        # Binds the queue to the specified exchange
        channel.queue_bind(queue=self.queueName,
                        exchange=self.config['exchange'],
                        routing_key=self.bindingKey)

        channel.basic_consume(queue=self.queueName,
                            on_message_callback=self.callback,
                            auto_ack=True)

        print('[*] Waiting for data for ' + self.queueName + '. To exit press CTRL+C')

        try:

            channel.start_consuming()

            channel.close()

        except KeyboardInterrupt:

            channel.stop_consuming()


queueName = 'reportsedc'
key = 'reportsedc'
notification_consumer_config = {'host': 'fishymq.xlab.si',
                                'port': 45672,
                                'exchange' : 'reportsedc',
                                'login':'tubs',
                                'password':'sbut'}

if __name__ == '__main__':

    def on_message_callback(channel, method, properties, body):

        print(" [x] Received %r" % body)
        info = json.loads(body.decode('utf-8'))
        print(info)

    try:

        init_rabbit = RMQsubscriberCR(queueName, key, notification_consumer_config, on_message_callback)
        init_rabbit.setup()

    except KeyboardInterrupt:

        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)