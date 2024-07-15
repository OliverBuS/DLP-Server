import logging
import re
import traceback
from io import BytesIO
from socketserver import ThreadingMixIn
from typing import Callable, Dict, Optional

from docx import Document

from file_operations.file_operations import DOCOperations, PDFOperations, TextOperations
from pyicap import BaseICAPRequestHandler, ICAPServer

logging.basicConfig(
    filename="pyicap.log", level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


class AnalysisResult:
    def __init__(self, censor_dict: dict, block: bool, block_message: str = "Content blocked due to policy violation"):
        self.censor_dict = censor_dict
        self.block = block
        self.block_message = block_message


class ContentAnalyzer:
    """
    ContentAnalyzer is responsible for analyzing plain text content and identifying sensitive information.

    Methods:
        analyze(content: str) -> dict:
            Analyzes the provided plain text content and returns a dictionary.
            The dictionary keys represent the sensitive information found within the content,
            and the values represent the replacement values for the sensitive information.
    """

    def analyze(self, content: str, origin_ip: str, destination_ip: str, file_name: str = None, metadata: dict = None):
        """
        Analyzes the provided plain text content and returns a dictionary.

        The method identifies sensitive information within the content and creates a dictionary.
        The keys of the dictionary are the sensitive information found, and the values are the
        corresponding replacement values.

        Parameters:
            content (str): The plain text content to be analyzed.

        Returns:
            dict:   A dictionary where the keys are the sensitive information found in the content,
                    and the values are the corresponding replacement values. If no sensitive information
                    is found, it returns None.
        """
        raise NotImplementedError("Subclasses must implement the analyze method")


class RequestAuthorizer:
    def authorize(self, request: bytes, request_headers: dict) -> bool:
        raise NotImplementedError("Subclasses must implement the authorize method")


class FileHandler:
    def __init__(self, content: bytes, content_analyzer: Callable[[bytes], None] = None) -> None:
        self.content = content
        self.file_content = None
        self.op_instance = TextOperations(content_analyzer)

        # Split the content based on the boundary string
        boundary = content.split(b"\r\n")[0][2:]
        parts = content.split(boundary) if boundary else [content]

        # Find the part containing the file content
        file_part = None
        for part in parts:
            if b'filename="' in part:
                file_part = part
                file_extension = None
                # Extract the filename using regex
                header = part.split(b"\r\n\r\n", 1)[0]
                match = re.search(rb'filename="(.+)"', header)
                if match:
                    filename = match.group(1).decode("utf-8")
                    file_extension = filename.split(".")[-1].lower()
                    print(f"Detected file extension: {file_extension}")
                break

        if file_part:
            # Extract the file content by removing headers and trailing newlines
            self.file_content = file_part.split(b"\r\n\r\n", 1)[1].strip()

            # Check if the content is a PDF
            if file_extension == "pdf" or self.file_content.startswith(b"%PDF"):
                self.op_instance = PDFOperations(content_analyzer)
            # Check if the content is a Word document
            elif file_extension == "docx":
                try:
                    Document(BytesIO(self.file_content))
                    self.op_instance = DOCOperations(content_analyzer)
                    return
                except Exception:
                    traceback.print_exc()
            # TODO: define how to manage other files

    def modify_content(self, censor_dict: dict) -> bytes:
        try:
            return self.op_instance.modify_content(self.content, self.file_content, censor_dict)
        except Exception as e:
            print(f"Error modifying document: {str(e)}")
            traceback.print_exc()
            return self.content

    def analyze_content(self) -> AnalysisResult:
        try:
            return self.op_instance.analyze_content(self.content, self.file_content)
        except Exception as e:
            print(f"Error analyzing document: {str(e)}")
            traceback.print_exc()


class ThreadingSimpleServer(ThreadingMixIn, ICAPServer):
    pass


class SimpleICAPHandler(BaseICAPRequestHandler):
    def __init__(self, request, client_address, server):
        self.content_analyzer = server.content_analyzer
        self.request_authorizer = server.request_authorizer
        super().__init__(request, client_address, server)

    def dlp_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b"Methods", b"REQMOD")
        self.set_icap_header(b"Service", b"SimpleICAP Server 1.0")
        self.set_icap_header(b"Preview", b"0")
        self.set_icap_header(b"Transfer-Preview", b"*")
        self.set_icap_header(b"Transfer-Ignore", b"jpg,jpeg,gif,png,swf,flv")
        self.set_icap_header(b"Transfer-Complete", b"")
        self.set_icap_header(b"Max-Connections", b"100")
        self.set_icap_header(b"Options-TTL", b"3600")
        self.send_headers(False)

    def dlp_REQMOD(self):

        if not self.has_body:
            self.no_adaptation_required()
            return

        prevbuf = b""  # Initialize content variable

        if self.preview:
            print("Handling preview mode")
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                prevbuf += chunk

            if self.ieof:
                print("End of preview")
                self.send_headers(True)
                if len(content) > 0:
                    self.write_chunk(content)
                self.write_chunk(b"")
                return

            self.cont()

        if not self.request_authorizer.authorize(self.enc_req, self.enc_req_headers):
            self.send_enc_error(403, message=b"Forbidden")
            return

        content = b""

        while True:
            chunk = self.read_chunk()
            if not chunk:
                break
            content += chunk

        file_handler = FileHandler(content, self.content_analyzer)
        print(f"FileHandler type {type(file_handler.op_instance)}")

        origin_ip = self.enc_req_headers.get(b"X-Client-IP", [b"127.0.0.1"])[0].decode("utf-8")
        destination_ip = self.enc_req_headers.get(b"X-Server-IP", [b"127.0.0.1"])[0].decode("utf-8")

        result = file_handler.analyze_content()

        logging.info("Result:")
        logging.info("Blocked: " + str(result.block))
        logging.info("Message: " + result.block_message)
        logging.info("Censor dict: " + str(result.censor_dict))

        if result.block:
            self.send_enc_error(403, body=result.block_message.encode("utf-8"))
            return

        if result.censor_dict:
            self.set_icap_response(200)
            modified_content = file_handler.modify_content(result.censor_dict)
            logging.info("Modified request")
            # logging.info(modified_content)
            self.set_enc_request(b" ".join(self.enc_req))
            self.set_content_length_header(str(len(modified_content)))
            print(f"Headers: {self.enc_req_headers}")
            self.send_headers(True)
            self.write_chunk(modified_content)
            self.write_chunk(b"")
        else:
            self.no_adaptation_required()

    def dlp_RESPMOD(self):
        if not self.has_body:
            self.no_adaptation_required()
            return

        prevbuf = b""  # Initialize content variable

        if self.preview:
            print("Handling preview mode")
            while True:
                chunk = self.read_chunk()
                if chunk == b"":
                    break
                prevbuf += chunk

            if self.ieof:
                print("End of preview")
                self.send_headers(True)
                if len(prevbuf) > 0:
                    self.write_chunk(prevbuf)
                self.write_chunk(b"")
                return

        self.cont()

        content = b""

        while True:
            chunk = self.read_chunk()
            if not chunk:
                break
            content += chunk

        logging.info("Original content in response")
        logging.info(content)

        self.no_adaptation_required()
        return

    def set_content_length_header(self, content_length):
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                if h.lower() == b"content-length":
                    v = content_length.encode("utf-8")
                self.set_enc_header(h, v)


class SimpleICAPServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1344,
        prefix: str = "dlp",
        content_analyzer: ContentAnalyzer = None,
        request_authorizer: RequestAuthorizer = None,
    ):
        self.host = host
        self.port = port
        self.prefix = prefix
        self.content_analyzer = content_analyzer
        self.request_authorizer = request_authorizer

    def start(self):
        class CustomHandler(SimpleICAPHandler):
            def __getattr__(self, name):
                if name.startswith(self.server.prefix + "_"):
                    return getattr(self, name.split("_", 1)[1])
                raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

        server = ThreadingSimpleServer(
            (self.host, self.port),
            CustomHandler,
        )
        server.content_analyzer = self.content_analyzer
        server.request_authorizer = self.request_authorizer
        server.prefix = self.prefix

        print(f"Starting ICAP server on {self.host}:{self.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Server stopped")
