import logging
import os
from urllib.parse import quote

from moto.s3 import responses as s3_responses

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    CreateBucketOutput,
    CreateBucketRequest,
    GetObjectOutput,
    GetObjectRequest,
    ListObjectsOutput,
    ListObjectsRequest,
    PutObjectOutput,
    PutObjectRequest,
    S3Api,
)
from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.protocol.serializer import S3ResponseSerializer
from localstack.config import get_edge_port_http, get_protocol
from localstack.constants import LOCALHOST_HOSTNAME, S3_VIRTUAL_HOSTNAME
from localstack.http import Request, Response
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch
from localstack.utils.strings import checksum_crc32, checksum_crc32c, hash_sha1, hash_sha256

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = f"s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()},{S3_VIRTUAL_HOSTNAME}"

LOG = logging.getLogger(__name__)


class InvalidRequestError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("InvalidRequest", message, 400, True)


def _create_context(request, operation_name, params=None):
    context = create_aws_request_context(
        service_name="s3", action=operation_name, parameters=params
    )
    # TODO doesn't work for curl requests
    context.request = request
    return context


class S3Provider(S3Api, ServiceLifecycleHook):
    def on_after_init(self):
        self.apply_patches()
        LOG.debug("-----> s3provider")

        @patch(s3_responses.S3Response._bucket_response_put)
        def _bucket_response_put(fn, self, request, region_name, bucket_name, querystring):
            result = fn(self, request, region_name, bucket_name, querystring)
            if "policy" in querystring:
                return 204, {}, ""
            return result

    @handler("CreateBucket", expand=False)
    def create_bucket(
        self, context: RequestContext, request: CreateBucketRequest
    ) -> CreateBucketOutput:
        response = call_moto(context)
        bucket = request.get("Bucket")

        # Location is always contained in response -> full url for LocationConstraint outside us-east-1
        if request.get("CreateBucketConfiguration"):
            location = request["CreateBucketConfiguration"].get("LocationConstraint")
            if location and location != "us-east-1":
                response[
                    "Location"
                ] = f"{get_protocol()}://{bucket}.s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        if "Location" not in response:
            response["Location"] = f"/{bucket}"

        # path style: https://s3.region-code.amazonaws.com/bucket-name/key-name

        # TODO consider region?
        # host_pattern_path_style = f"s3.<regex('({AWS_REGION_REGEX}\.)?'):region>{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        # host_pattern_path_style = f"s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"

        # TODO routes interfere with other put/get requests by botocore
        # ROUTER.add(
        #     f"/<regex('{bucket}'):bucket>/<path:path>",
        #     endpoint=self.serve_bucket_content,
        # )
        # ROUTER.add(
        #     f"/<regex('{bucket}'):bucket>",
        #     endpoint=self.serve_bucket_content,
        #     defaults={"path": ""},
        #     methods=["GET"],
        # )

        # virtual-host style: https://bucket-name.s3.region-code.amazonaws.com/key-name
        # host_pattern_vhost_style = f"{bucket}.s3.<regex('({AWS_REGION_REGEX}\.)?'):region>{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        # TODO this rule does not work yet
        # host_pattern_vhost_style = f"{bucket}.s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        #
        # ROUTER.add(
        #     "/<path:path>",
        #     host=host_pattern_vhost_style,
        #     defaults={"path": "", "bucket": ""},
        #     endpoint=self.serve_bucket_content,
        #     methods=["GET"],
        # )

        return response

    def serve_bucket_list(self, request: Request) -> Response:
        bucket = request.url.split("://")[1].split(".")[0]
        if request.method == "GET":
            client = aws_stack.connect_to_service("s3")
            data = client.list_objects(Bucket=bucket)
            return data  # TODO this should return xml-response

    def serve_bucket_content(self, request: Request, bucket: str, path: str) -> Response:
        # bucket = request.path.split("/")[1]
        LOG.debug("------> serve_bucket_content")
        if not bucket and not path:
            # TODO is this actual expected, should be prevented?
            # internal request was re-routed
            splitted = request.url.split("://")[1].split("/")
            if len(splitted) == 3:
                bucket = splitted[-2]
                path = [-1]
            elif len(splitted) == 2:
                bucket = [-1]
            else:
                LOG.error(f"unexpected input for server_bucket_content from url {request.url}")
        if not bucket:
            bucket = request.url.split("://")[1].split(".")[0]
        key = path
        # region = ?

        if request.method == "GET":
            if key:
                get_object_request = GetObjectRequest(Bucket=bucket, Key=key)
                # TODO handle not found
                # TODO request does not work for url (only get-object) -> request header?
                data = self.get_object(
                    _create_context(request, "GetObject", {"Bucket": bucket, "Key": key}),
                    get_object_request,
                )
                return Response(data["Body"].read())
            else:
                context = _create_context(request, "ListObjects", {"Bucket": bucket})
                data = self.list_objects(
                    context,
                    ListObjectsRequest(Bucket=bucket),
                )
                serializer = S3ResponseSerializer()
                return serializer.serialize_to_response(data, context.operation, request.headers)

        if request.method == "PUT":
            if key:
                # TODO is this enough?
                return call_moto(
                    _create_context(request, "PutObject", {"Bucket": bucket, "Key": key})
                )

    @handler("GetObject", expand=False)
    def get_object(self, context: RequestContext, request: GetObjectRequest) -> GetObjectOutput:
        response = call_moto(context)
        response["AcceptRanges"] = "bytes"
        return GetObjectOutput(response)

    @handler("ListObjects", expand=False)
    def list_objects(
        self, context: RequestContext, request: ListObjectsRequest
    ) -> ListObjectsOutput:
        response = call_moto(context)
        if "Marker" not in response:
            response["Marker"] = ""
        if "Delimiter" in response and response["Delimiter"] != "/":
            # fix url-encoding
            response["Delimiter"] = quote(response["Delimiter"])
        return ListObjectsOutput(response)

    @handler("PutObject", expand=False)
    def put_object(self, context: RequestContext, request: PutObjectRequest) -> PutObjectOutput:
        if context.request.headers.get("x-amz-sdk-checksum-algorithm"):
            data = context.request.data  # TODO
            _validate_checksum(data, context.request.headers)
        response = call_moto(context)
        return PutObjectOutput(response)


def _validate_checksum(data, headers):
    algorithm = headers.get("x-amz-sdk-checksum-algorithm", "")
    checksum_header = f"x-amz-checksum-{algorithm.lower()}"
    received_checksum = headers.get(checksum_header)

    calculated_checksum = ""
    match algorithm:
        case "CRC32":
            calculated_checksum = checksum_crc32(data)

        case "CRC32C":
            calculated_checksum = checksum_crc32c(data)

        case "SHA1":
            calculated_checksum = hash_sha1(data)

        case "SHA256":
            calculated_checksum = hash_sha256(data)

        case _:
            raise InvalidRequestError(
                "The value specified in the x-amz-trailer header is not supported"
            )

    if calculated_checksum != received_checksum:
        raise InvalidRequestError(f"Value for {checksum_header} header is invalid.")
