import logging
import socket
from functools import partial
from typing import Dict, List

import msgpack
import pika
from pika.adapters.select_connection import SelectConnection
from pika.channel import Channel
from pika.exceptions import (
    AMQPChannelError,
    AMQPConnectionError,
    ConnectionClosedByBroker,
)
from pika.frame import Method

from ..contrib.django.conf import (
    KC_UTILS_CONSUMER_QUEUES,
    KC_UTILS_CREATE_QUEUES,
    RABBITMQ_URL,
)

logger = logging.getLogger(__name__)


class EventHandler:
    @staticmethod
    def process_message(event_data: Dict) -> bool:
        from .django.strategies import EventTypeStrategyClassFactory

        logger.info(f"the received event data is {event_data}")
        base_event_strategy = event_data["event_type"].split("_")[0]
        operation_type = (
            event_data.get("data", {}).get("operation_type", "").split(".")[0]
        )
        event_type = event_data.get("data", {}).get("operation_type", "").split(".")[1]

        if (
            "user_id" in event_data["data"].get("operation_information", {}).keys()
            and (operation_type == "ASSIGN" or operation_type == "REMOVE")
            and event_type == "Role"
        ):
            operation_type = "UPDATE"
            event_type = "User"

        try:
            event_factory = EventTypeStrategyClassFactory().handle_event_type(
                base_event_strategy
            )
            strategy = event_factory.handle_event_type(event_type)

        except KeyError as e:
            logger.warning(e)
            return False

        strategy.process(event_data, operation_type, event_type)
        return True


class EventConsumer(EventHandler):
    def __init__(self):
        self.connection = None
        self.channel = None
        self.url = RABBITMQ_URL
        self.main_exchange = "eventbus.exchange"
        self.dlx_exchange = "eventbus.exchange.dlx"
        self.user_sync_ttl = 900000
        self.dlx_ttl = 100000
        self.queue_reg = self.QueueRegistry()
        self.register_queue = partial(self.queue_reg.register_queue)
        self.publish_connection = None
        self.publish_channel = None
        self._retry_attempt = 0
        self.max_retries = 10

    class QueueRegistry:
        def __init__(self):
            self._registry = {"create": [], "sync": []}
            self._initialize_queues()

        def _initialize_queues(self) -> None:
            self.register_queue(KC_UTILS_CREATE_QUEUES, queue_status="create")
            self.register_queue(KC_UTILS_CONSUMER_QUEUES, queue_status="sync")

        def _register_queues_from_dict(
            self, queue_dict: Dict, queue_status: str
        ) -> None:
            for queue_type, queues in queue_dict.items():
                for queue_name in queues:
                    routing_key = (
                        f"eventbus.{queue_type}.{queue_name}"
                        if queue_type != "general"
                        else "#"
                    )
                    queue_name = (
                        f"{queue_type}.{queue_name}"
                        if queue_type != "general"
                        else queue_name
                    )
                    self._registry[queue_status].append(
                        {"queue": queue_name, "routing_key": routing_key}
                    )

        def register_queue(
            self, queue: dict | str, routing_key=None, queue_status="create"
        ):
            if queue_status not in self._registry:
                raise ValueError(f"Unsupported queue status: {queue_status}")

            if isinstance(queue, dict):
                self._register_queues_from_dict(queue, queue_status)
            else:
                self._registry[queue_status].append(
                    {"queue": queue, "routing_key": routing_key}
                )

        def get_registry(self) -> Dict[str, List]:
            return self._registry

        def get_queues(self, queue_type: str) -> List:
            return self._registry.get(queue_type, None)

        def list_queues_dict(self) -> Dict[str, List]:
            return self._registry

    def on_queue_declared(self, method_frame: Method) -> None:
        queue_name = method_frame.method.queue
        logger.info(f"consuming Queue {queue_name}")
        exception_map = {
            AMQPConnectionError: "Connection error",
            AMQPChannelError: "Channel error",
            ConnectionClosedByBroker: "Connection closed by broker",
        }
        try:
            self.channel.basic_consume(
                queue=queue_name, on_message_callback=self.handle_message
            )
        except Exception as e:
            message = exception_map.get(type(e), "Unexpected error")
            logger.error(f"{message}: {e}")

    def stop(self) -> None:
        if self.connection and not self.connection.is_closed:
            logger.info("Closing connection...")
            self.connection.close()
        if self.connection and self.connection.ioloop:
            logger.info("Stopping IOLoop...")
            self.connection.ioloop.stop()
        logger.info("Stopped consuming messages")

    def reject_callback(self, ch, method, properties, body):
        logger.info(f"Rejecting message: {self.decode_event(body)}")
        ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)

    @staticmethod
    def decode_event(body: bytes) -> Dict:
        return msgpack.unpackb(body, raw=False)

    def handle_message(self, ch, method, properties, body):
        event_data = self.decode_event(body)
        processed = self.process_message(event_data)
        if processed:
            ch.basic_ack(delivery_tag=method.delivery_tag)
        else:
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    def establish_connection(self) -> None:
        parameters = pika.URLParameters(self.url)
        self.connection = pika.SelectConnection(
            parameters=parameters,
            on_open_callback=self.on_connection_open,
            on_open_error_callback=self.on_connection_error,
            on_close_callback=self.on_connection_close,
        )
        try:
            self.connection.ioloop.start()
        except KeyboardInterrupt:
            logger.info("Ctrl+C detected. Stopping...")
            self.stop()
            raise SystemExit(0)

    def on_connection_open(self, connection: SelectConnection) -> None:
        logger.info(f"Connection opened {connection}")
        self._retry_attempt = 0
        self.connection.channel(on_open_callback=self.on_channel_open)

    def on_connection_error(
        self, connection: SelectConnection, error: Exception
    ) -> None:
        logger.error(f"Connection error: {error}")

        self._retry_attempt += 1
        if self._retry_attempt > self.max_retries:
            logger.error("Maximum reconnection attempts reached. Exiting...")
            connection.ioloop.stop()
            self.stop()
            raise SystemExit(1)

        delay = min(2 * (2 ** (self._retry_attempt - 1)), 30)
        logger.info(f"Retry attempt {self._retry_attempt} in {delay} seconds...")

        if not connection.is_closed:
            try:
                connection.close()
            except:
                pass

        connection.ioloop.call_later(delay, self.establish_connection)

    def on_connection_close(
        self, connection: SelectConnection, reason: Exception | str
    ) -> None:
        logger.warning(f"Connection {connection} closed: {reason}")
        self.stop()

    def on_channel_open(self, channel: Channel) -> None:
        logger.info("Channel opened")
        self.channel = channel
        self.run_routine()

    def run_routine(self) -> None:
        if not self.queue_reg:
            logger.warning(
                "queue registry is empty please register a queue or assign env var value"
            )
            return
        for queue_status, queues in self.queue_reg.list_queues_dict().items():
            for queue_params in queues:
                self.setup_queue_and_dlx(
                    queue_params,
                    callback=self.on_queue_declared if queue_status == "sync" else None,
                )

    def setup_queue_and_dlx(self, params: dict, callback=None) -> None:
        queue = params["queue"]
        routing_key = params["routing_key"]
        dlx_queue = f"{queue}-dlx"
        dlx_routing_key = f"{routing_key}-dlx"

        try:
            self.channel.exchange_declare(
                exchange=self.main_exchange, exchange_type="topic", durable=True
            )
            self.channel.exchange_declare(
                exchange=self.dlx_exchange, exchange_type="topic", durable=True
            )

            self.channel.queue_declare(
                queue=queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": self.dlx_exchange,
                    "x-dead-letter-routing-key": dlx_queue,
                    "x-message-ttl": self.user_sync_ttl,
                },
                callback=callback,
            )
            logger.info(f"Queue {queue} Declared")

            self.channel.queue_bind(
                exchange=self.main_exchange,
                queue=queue,
                routing_key=routing_key,
            )

            self.channel.queue_declare(
                queue=dlx_queue,
                durable=True,
                arguments={"x-message-ttl": self.dlx_ttl},
                callback=callback,
            )
            self.channel.queue_bind(
                exchange=self.dlx_exchange,
                queue=dlx_queue,
                routing_key=dlx_routing_key,
            )

            self.channel.basic_qos(prefetch_count=1)

        except socket.gaierror as e:
            logger.error(f"DNS resolution error while connecting to RabbitMQ: {e}")

        except Exception as e:
            logger.error(f"connection error {e}")


class EventAPIHandler(EventHandler): ...
