class AWSCheckerBase:
    def __init__(self, session):
        self.session = session
        self.clients = {}
        self.region = session.region_name

    def get_client(self, service):
        if service not in self.clients:
            self.clients[service] = self.session.client(service)
        return self.clients[service]

    def paginate(self, client_method, **kwargs):
        paginator = self.get_client(
            client_method.__self__.__class__.__name__.lower()
        ).get_paginator(client_method.__name__)
        return paginator.paginate(**kwargs)


class ComplianceCheckResult:
    def __init__(self, check_id, status, evidence=None, remediation=None):
        self.check_id = check_id
        self.status = status  # PASS/FAIL/ERROR
        self.evidence = evidence or []
        self.remediation = remediation or []
