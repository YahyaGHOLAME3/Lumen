class LumenException(Exception):
    def __init__(self, message='Lumen Base Exception'):
        self._message = message

    def __str__(self):
        return self._message


class FuzzerException(LumenException):
    def __init__(self, message='Fuzzer Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class HostHandlerException(LumenException):
    def __init__(self, message='Host Handler Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class ScannerException(LumenException):
    def __init__(self, message='Scanner Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class WAFException(LumenException):
    def __init__(self, message='WAF Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class RequestHandlerException(LumenException):

    def __init__(self, message='RequestHandler Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class RequestHandlerConnectionReset(RequestHandlerException):

    def __init__(self, message='Connection Reset'):
        super().__init__(message)

    def __str__(self):
        return self._message


class WebAppScannerException(LumenException):
    def __init__(self, message='Web Application Scanner Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message


class WebServerValidatorException(LumenException):
    def __init__(self, message='Web Server Validator Exception'):
        super().__init__(message)

    def __str__(self):
        return self._message
