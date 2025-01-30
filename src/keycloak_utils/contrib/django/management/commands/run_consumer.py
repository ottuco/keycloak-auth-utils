import logging
import signal
import sys

from django.core.management.base import BaseCommand

from keycloak_utils.consumer.core import EventConsumer

logger = logging.getLogger("keycloak_event_consumer")


class Command(BaseCommand):
    help = "Run the Keycloak event consumer"
    queues_reg = []

    def add_arguments(self, parser):
        parser.add_argument(
            "--users-queues",
            nargs="*",
            default=[],
            help="Space-separated list of user queues (e.g., user_queue1 user_queue2).",
        )
        parser.add_argument(
            "--payment-queues",
            nargs="*",
            default=[],
            help="Space-separated list of payment queues (e.g., payment_queue1 payment_queue2).",
        )
        parser.add_argument(
            "--general-queues",
            nargs="*",
            default=[],
            help="Space-separated list of general queues (e.g., general_queue1 general_queue2).",
        )
        parser.add_argument(
            "--users-consumer-queues",
            nargs="*",
            default=[],
            help="Space-separated list of user queues (e.g., user_queue1 user_queue2).",
        )
        parser.add_argument(
            "--payment-consumer-queues",
            nargs="*",
            default=[],
            help="Space-separated list of payment queues (e.g., payment_queue1 payment_queue2).",
        )
        parser.add_argument(
            "--general-consumer-queues",
            nargs="*",
            default=[],
            help="Space-separated list of general queues (e.g., general_queue1 general_queue2).",
        )

    def handle(self, *args, **options):
        create_queues = {
            "users": options["users_queues"],
            "payment": options["payment_queues"],
            "general": options["general_queues"],
        }

        consumer_queues = {
            "users": options["users_consumer_queues"],
            "payment": options["payment_consumer_queues"],
            "general": options["general_consumer_queues"],
        }

        consumer = EventConsumer()

        consumer.register_queue(create_queues, queue_status="create")
        consumer.register_queue(consumer_queues, queue_status="sync")

        for queue in self.queues_reg:
            consumer.register_queue(*queue)

        self.stdout.write(self.style.SUCCESS("Starting Keycloak event consumer"))
        consumer.establish_connection()
        self.stdout.write(
            self.style.SUCCESS("Received shutdown signal. Stopping consumers..."),
        )
