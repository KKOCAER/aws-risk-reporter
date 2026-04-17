"""Placeholder DynamoDB store for the next iteration."""


class DDBStore:
    def __init__(self, table_name: str = "security-hub-action-center"):
        self.table_name = table_name

    def save_finding(self, finding: dict):
        raise NotImplementedError("Implement DynamoDB persistence in the next iteration.")
