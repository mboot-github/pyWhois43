import sys


class HasReporting:
    def __init__(
        self,
        verbose: bool = False,
    ) -> None:
        self.verbose = verbose

    def reportFuncName(self) -> None:
        if not self.verbose:
            return

        frame = sys._getframe(1)
        if frame is None:
            return

        message = (
            "{} {}".format(
                frame.f_code.co_filename,
                frame.f_code.co_name,
            ),
        )
        print(message, file=sys.stderr)
