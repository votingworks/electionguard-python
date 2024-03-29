from unittest import TestCase

from electionguard.logs import (
    get_stream_handler,
    log_add_handler,
    log_remove_handler,
    log_handlers,
    log_debug,
    log_error,
    log_info,
    log_warning,
)


class TestLogs(TestCase):
    def test_log_methods(self) -> None:
        # Arrange
        message = "test log message"

        # Act
        log_debug(message)
        log_error(message)
        log_info(message)
        log_warning(message)

    def test_log_handlers(self) -> None:
        # Arrange

        # Act
        handlers = log_handlers()

        # Assert
        self.assertEqual(len(handlers), 1)

        # Act
        log_remove_handler(handlers[0])
        empty_handlers = log_handlers()

        # Assert
        self.assertEqual(len(empty_handlers), 0)

        # Act
        log_add_handler(get_stream_handler())
        added_handlers = log_handlers()

        # Assert
        self.assertEqual(len(added_handlers), 1)
