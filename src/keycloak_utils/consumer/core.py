import logging
import socket
from functools import partial
from typing import Dict, List

import msgpack
import pika
from celery.bin.amqp import exchange_declare
from pika.adapters.select_connection import SelectConnection
from pika.channel import Channel
from pika.exceptions import (
    AMQPChannelError,
    AMQPConnectionError,
    ConnectionClosedByBroker,
)
from pika.spec import Basic, BasicProperties

from ..contrib.django.conf import (
    KC_UTILS_CONSUMER_QUEUES,
    KC_UTILS_CREATE_QUEUES,
    RABBITMQ_URL,
)

logger = logging.getLogger(__name__)


class EventHandler:
    """
    Handles the processing of event messages by determining the appropriate strategy
    based on the event type and operation type.
    """

    @staticmethod
    def process_message(event_data: Dict) -> bool:
        """
        Processes an event message by determining its event and operation type,
        and invoking the appropriate strategy to handle it.

        Args:
            event_data (Dict): The event data containing event type, operation type,
            and operation information.

        Returns:
            bool: True if the event is successfully processed, False otherwise.
        """
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
                base_event_strategy,
            )
            strategy = event_factory.handle_event_type(event_type)

        except KeyError as e:
            logger.warning(e)
            return False

        strategy.process(event_data, operation_type, event_type)
        return True


class EventConsumer(EventHandler):
    """
    Consumer class that extends EventHandler to process messages from RabbitMQ.
    Manages connections, queue registration, and message handling routines.
    """

    def __init__(self):
        """
        Initializes EventConsumer with RabbitMQ connection parameters,
        queue registry, and retry mechanism.
        """
        self.connection = None
        self.channel = None
        self.url = RABBITMQ_URL
        self.main_exchange = "eventbus.exchange"
        self.dlx_exchange = "eventbus.exchange.dlx"
        self.user_sync_ttl = 90000
        self.dlx_ttl = 10000
        self.queue_reg = self.QueueRegistry()
        self.register_queue = partial(self.queue_reg.register_queue)
        self.publish_connection = None
        self.publish_channel = None
        self._retry_attempt = 0
        self.max_retries = 10

    class QueueRegistry:
        """
        Registry for managing and initializing RabbitMQ queues.
        """

        def __init__(self):
            self._registry = {"create": [], "sync": []}
            self._initialize_queues()

        def _initialize_queues(self) -> None:
            """
            Initializes the queue registry by registering default queues.
            """
            self.register_queue(KC_UTILS_CREATE_QUEUES, queue_status="create")
            self.register_queue(KC_UTILS_CONSUMER_QUEUES, queue_status="sync")

        def _register_queues_from_dict(
            self,
            queue_dict: Dict,
            queue_status: str,
        ) -> None:
            """
            Registers queues from a dictionary.

            Args:
                queue_dict (Dict): Dictionary containing queue configurations.
                queue_status (str): Queue status (e.g., 'create', 'sync').
            """
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
                        {"queue": queue_name, "routing_key": routing_key},
                    )

        def register_queue(
            self,
            queue: dict | str,
            routing_key=None,
            queue_status="create",
        ):
            """
            Registers a queue in the registry.

            Args:
                queue (dict | str): Queue configuration or name.
                routing_key (str, optional): Routing key for the queue.
                queue_status (str): Queue status (e.g., 'create', 'sync').
            """
            if queue_status not in self._registry:
                raise ValueError(f"Unsupported queue status: {queue_status}")

            if isinstance(queue, dict):
                self._register_queues_from_dict(queue, queue_status)
            else:
                self._registry[queue_status].append(
                    {"queue": queue, "routing_key": routing_key},
                )

        def get_registry(self) -> Dict[str, List]:
            """
            Retrieves the full queue registry.

            Returns:
                Dict[str, List]: Registry of queues.
            """
            return self._registry

        def get_queues(self, queue_type: str) -> List:
            """
            Retrieves queues of a specific type.

            Args:
                queue_type (str): Queue type (e.g., 'create', 'sync').

            Returns:
                List: List of queues for the specified type.
            """
            return self._registry.get(queue_type, None)

        def list_queues_dict(self) -> Dict[str, List]:
            """
            Lists all registered queues.

            Returns:
                Dict[str, List]: Dictionary of registered queues.
            """
            return self._registry

    def stop(self) -> None:
        """
        Gracefully stops the connection and I/O loop.
        """
        if self.connection and not self.connection.is_closed:
            logger.info("Closing RabbitMQ connection...")
            self.connection.close()
        if self.connection and self.connection.ioloop:
            logger.info("Stopping IOLoop...")
            self.connection.ioloop.stop()
        logger.info("Stopped consuming messages.")

    def reject_callback(self, ch, method, properties, body):
        """
        Rejects a message and prevents it from being requeued.

        Args:
            ch: The channel object.
            method: Delivery method.
            properties: Message properties.
            body: Message body.
        """
        logger.info(f"Rejecting message: {self.decode_event(body)}")
        ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)

    @staticmethod
    def decode_event(body: bytes) -> Dict:
        """
        Decodes an event message.

        Args:
            body (bytes): Encoded message body.

        Returns:
            Dict: Decoded event data.
        """
        return msgpack.unpackb(body, raw=False)

    def on_queue_declared(self, method_frame) -> None:
        """
        Callback invoked when a queue is successfully declared.

        Args:
            method_frame: Frame containing queue declaration details.
        """
        queue_name = method_frame.method.queue
        logger.info(f"Consuming from queue: {queue_name}")

        exception_map = {
            AMQPConnectionError: "Connection error",
            AMQPChannelError: "Channel error",
            ConnectionClosedByBroker: "Connection closed by broker",
        }

        try:
            callback = (
                self.dlx_handle_message
                if queue_name[-4:] == "-dlx"
                else self.handle_message
            )
            self.channel.basic_consume(queue=queue_name, on_message_callback=callback)
        except Exception as e:
            message = exception_map.get(type(e), "Unexpected error")
            logger.error(f"{message}: {e}")

    def handle_message(
        self,
        channel: Channel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes,
    ):
        """
        Processes an incoming message.

        Args:
            ch: The channel object.
            method: Delivery method.
            properties: Message properties.
            body: Message body.
        """
        event_data = self.decode_event(body)
        processed = self.process_message(event_data)

        if processed:
            channel.basic_ack(delivery_tag=method.delivery_tag)
        else:
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

    def dlx_handle_message(
        self,
        channel: Channel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes,
    ) -> None:
        """
        Callback function to requeue messages from DLX to the main queue.

        Args:
            channel (Channel): The RabbitMQ channel.
            method (Basic.Deliver): The method frame containing delivery information.
            properties (BasicProperties): The properties of the message, including headers.
            body (bytes): The message body.

        Raises:
            Exception: Reraises any unhandled exception to ensure proper handling upstream.
        """
        routing_key = method.routing_key.replace("-dlx", "")
        try:
            x_death = (
                properties.headers.get("x-death", []) if properties.headers else []
            )
            if x_death and isinstance(x_death, list):
                details = x_death[0]
                reason = details.get("reason", "unknown")
                original_queue = details.get("queue", "unknown")
                count = details.get("count", 0)
                logger.info(
                    "Message dead-lettered. Reason: %s, Original Queue: %s, Retry Count: %d",
                    reason,
                    original_queue,
                    count,
                )
            else:
                logger.warning(
                    "Message dead-lettered but missing or invalid x-death details.",
                )
        except Exception as e:
            logger.error(
                "Error extracting dead-lettering information: %s",
                e,
                exc_info=True,
            )

        try:
            channel.basic_publish(
                exchange=self.dlx_exchange + "-dlx",
                routing_key=routing_key,
                body=body,
                properties=properties,
            )
            channel.basic_ack(delivery_tag=method.delivery_tag)
            logger.info(
                "Message requeued to %s using routing key %s: %s",
                self.dlx_exchange + "-dlx",
                routing_key,
                self.decode_event(body),
            )
        except Exception as e:
            logger.error("Failed to requeue message: %s", e, exc_info=True)
            try:
                channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            except Exception as nack_error:
                logger.critical(
                    "Failed to nack message after requeue failure: %s",
                    nack_error,
                    exc_info=True,
                )

    def establish_connection(self) -> None:
        """
        Establishes a RabbitMQ connection and starts the I/O loop.
        """
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
        """
        Callback invoked when the connection is successfully opened.

        Args:
            connection (SelectConnection): The connection object.
        """
        logger.info("RabbitMQ connection opened.")
        self._retry_attempt = 0
        self.connection.channel(on_open_callback=self.on_channel_open)

    def on_connection_error(
        self,
        connection: SelectConnection,
        error: Exception,
    ) -> None:
        """
        Callback invoked when the connection fails to open.

        Args:
            connection (SelectConnection): The connection object.
            error (Exception): Error that occurred.
        """
        logger.error(f"Connection error: {error}")

        self._retry_attempt += 1
        if self._retry_attempt > self.max_retries:
            logger.error("Maximum retries reached. Exiting...")
            connection.ioloop.stop()
            self.stop()
            raise SystemExit(1)

        delay = min(2**self._retry_attempt, 30)
        logger.info(f"Retrying connection in {delay} seconds...")
        connection.ioloop.call_later(delay, self.establish_connection)

    def on_connection_close(
        self,
        connection: SelectConnection,
        reason: Exception | str,
    ) -> None:
        """
        Callback invoked when the connection is closed.

        Args:
            connection (SelectConnection): The connection object.
            reason (Exception | str): Reason for closure.
        """
        logger.warning(f"RabbitMQ connection closed: {reason}")
        self.stop()

    def on_channel_open(self, channel: Channel) -> None:
        """
        Callback invoked when the channel is successfully opened.

        Args:
            channel (Channel): The channel object.
        """
        logger.info("RabbitMQ channel opened.")

        self.channel = channel
        self.channel.exchange_declare(
            exchange=self.main_exchange,
            exchange_type="topic",
            durable=True,
        )
        self.channel.exchange_declare(
            exchange=self.dlx_exchange,
            exchange_type="topic",
            durable=True,
        )
        self.channel.exchange_declare(
            exchange=self.dlx_exchange + "-dlx",
            exchange_type="direct",
            durable=True,
        )
        self.run_routine()

    def run_routine(self) -> None:
        """
        Routine to set up queues and start consuming messages.
        """
        if not self.queue_reg:
            logger.warning(
                "Queue registry is empty. Register a queue or assign environment variables.",
            )
            return

        for queue_status, queues in self.queue_reg.list_queues_dict().items():
            for queue_params in queues:
                self.setup_queue_and_dlx(
                    queue_params,
                    callback=self.on_queue_declared if queue_status == "sync" else None,
                )

    def setup_queue_and_dlx(self, params: dict, callback=None) -> None:
        """
        Sets up a main queue, a dead-letter exchange (DLX), and binds them with routing keys.

        Args:
            params (dict): Contains queue configuration.
                - queue (str): The name of the main queue.
                - routing_key (str): The routing key for the main queue.
            callback (callable, optional): A function to invoke when a queue is declared.

        Functionality:
            1. Declares a main exchange (`self.main_exchange`) for normal message flow.
            2. Declares a DLX exchange (`self.dlx_exchange`) for dead-letter handling.
            3. Declares the main queue with:
                - A TTL (`self.user_sync_ttl`) for message expiration.
                - Dead-letter configurations pointing to the DLX exchange.
            4. Declares a DLX queue for dead-letter messages with its own TTL.
            5. Binds the main queue to the main exchange and the DLX queue to the DLX exchange.

        Raises:
            socket.gaierror: If there is a DNS resolution issue.
            Exception: For any other connection-related errors.
        """

        queue = params["queue"]
        routing_key = params["routing_key"]
        dlx_queue = f"{queue}-dlx"
        dlx_routing_key = (
            f"{routing_key}-dlx"
            if routing_key != "#"
            else f"eventbus.general.{queue}-dlx"
        )

        try:
            self.channel.queue_declare(
                queue=queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": self.dlx_exchange,
                    "x-dead-letter-routing-key": dlx_routing_key,
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

            if routing_key == "#":
                routing_key = f"eventbus.general.{queue}"

            self.channel.queue_bind(
                exchange=self.dlx_exchange + "-dlx",
                queue=queue,
                routing_key=routing_key,
            )

            self.channel.queue_declare(
                queue=dlx_queue,
                durable=True,
                arguments={
                    "x-dead-letter-exchange": self.dlx_exchange + "-dlx",
                    "x-dead-letter-routing-key": routing_key,
                    "x-message-ttl": self.dlx_ttl,
                },
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
