import logging
import signal
import sys

from django.core.management.base import BaseCommand

from keycloak_utils.consumer.core import KeycloakEventConsumer

logger = logging.getLogger("keycloak_event_consumer")


class Command(BaseCommand):
    help = "Run the Keycloak event consumer"

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
            "--users-sync-queues",
            nargs="*",
            default=[],
            help="Space-separated list of user queues (e.g., user_queue1 user_queue2).",
        )
        parser.add_argument(
            "--payment-sync-queues",
            nargs="*",
            default=[],
            help="Space-separated list of payment queues (e.g., payment_queue1 payment_queue2).",
        )
        parser.add_argument(
            "--general-sync-queues",
            nargs="*",
            default=[],
            help="Space-separated list of general queues (e.g., general_queue1 general_queue2).",
        )

    queues_reg = []

    def handle(self, *args, **options):
        create_queues = {
            "users": options["users_queues"],
            "payment": options["payment_queues"],
            "general": options["general_queues"],
        }

        sync_queues = {
            "users": options["users_sync_queues"],
            "payment": options["payment_sync_queues"],
            "general": options["general_sync_queues"],
        }

        consumer = KeycloakEventConsumer()

        consumer.register_queue(create_queues, queue_status="create")
        consumer.register_queue(sync_queues, queue_status="sync")

        for queue in self.queues_reg:
            consumer.register_queue(*queue)

        consumer.establish_connection()

        def signal_handler(signum, frame):
            self.stdout.write(
                self.style.WARNING("Received shutdown signal. Stopping consumers...")
            )
            consumer.stop()
            sys.exit(0)

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        self.stdout.write(self.style.SUCCESS("Starting Keycloak event consumer"))
