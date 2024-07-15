import json
import logging
from typing import Dict, List

from dlp import DLP, Database
from icapserver import (
    AnalysisResult,
    ContentAnalyzer,
    RequestAuthorizer,
    SimpleICAPServer,
)

logging.basicConfig(
    filename="files_recieved.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class DLPContentAnalyzer(ContentAnalyzer):
    def __init__(self):
        self.db = Database("127.0.0.1", "dlp", "oliver", "oliver")
        self.dlp = DLP(db=self.db)

    def analyze(
        self,
        content: str,
        origin_ip: str = "127.0.0.1",
        destination_ip: str = "127.0.0.1",
        file_name: str = None,
        metadata: dict = None,
    ) -> AnalysisResult:

        metadata_dict = metadata or {}
        if file_name:
            metadata_dict["file_name"] = file_name

        # Log the file reception details
        log_message = f"Received file: {file_name}, with content: {content[:100]} from {origin_ip} to {destination_ip}"
        logging.info(log_message)
        print(log_message)

        result = self.dlp.analyze_network(
            text=content, origin_ip=origin_ip, destination_ip=destination_ip, metadata=json.dumps(metadata_dict)
        )
        return AnalysisResult(result.censor_dict, result.block, result.block_message)


class DLPRequestAuthorizer(RequestAuthorizer):
    def authorize(self, request: List[bytes], request_headers: dict) -> bool:
        # Implement your authorization logic here
        # For now, we'll allow all requests
        return True


def main():
    analyzer = DLPContentAnalyzer().analyze
    authorizer = DLPRequestAuthorizer()

    server = SimpleICAPServer(
        host="127.0.0.1",
        port=1344,
        prefix="dlp",
        content_analyzer=analyzer,
        request_authorizer=authorizer,
    )

    print("Starting DLP ICAP Server...")
    server.start()


if __name__ == "__main__":
    main()
