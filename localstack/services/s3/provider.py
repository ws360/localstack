import os
from urllib.parse import quote

from moto.s3 import responses as s3_responses
from moto.s3 import s3_backends

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.s3 import (
    AccountId,
    BucketName,
    ChecksumAlgorithm,
    ConfirmRemoveSelfBucketAccess,
    ContentMD5,
    CreateBucketOutput,
    CreateBucketRequest,
    GetObjectOutput,
    GetObjectRequest,
    ListObjectsOutput,
    ListObjectsRequest,
    Policy,
    PutObjectOutput,
    PutObjectRequest,
    S3Api,
)
from localstack.config import get_edge_port_http, get_protocol
from localstack.constants import LOCALHOST_HOSTNAME, S3_VIRTUAL_HOSTNAME
from localstack.http import Request, Response
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto, proxy_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch
from localstack.utils.strings import checksum_crc32, checksum_crc32c, hash_sha1, hash_sha256

os.environ[
    "MOTO_S3_CUSTOM_ENDPOINTS"
] = f"s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()},{S3_VIRTUAL_HOSTNAME}"


class InvalidRequestError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("InvalidRequest", message, 400, True)


def s3_global_backend():
    """Return the single/global backend used by moto"""
    return s3_backends["global"]


class S3Provider(S3Api, ServiceLifecycleHook):
    def on_after_init(self):
        self.apply_patches()

    def apply_patches(self):
        @patch(s3_responses.S3Response._bucket_response_head)
        def _bucket_response_head(fn, self, bucket_name, *args, **kwargs):
            code, headers, body = fn(self, bucket_name, *args, **kwargs)
            bucket = s3_global_backend().get_bucket(bucket_name)
            headers["x-amz-bucket-region"] = bucket.region_name
            return code, headers, body

        @patch(s3_responses.S3Response._bucket_response_get)
        def _bucket_response_get(fn, self, bucket_name, querystring, *args, **kwargs):
            result = fn(self, bucket_name, querystring, *args, **kwargs)
            # for some reason in the "get-bucket-location" call, moto doesn't return a code/headers/body triple as a result
            if isinstance(result, tuple) and len(result) == 3:
                code, headers, body = result
                bucket = s3_global_backend().get_bucket(bucket_name)
                headers["x-amz-bucket-region"] = bucket.region_name
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
        # host_pattern_path_style = f"s3.<regex('({AWS_REGION_REGEX}\.)?'):region>{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        # host_pattern_path_style = f"s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"

        # ROUTER.add(
        #     f"/{bucket}/<path:path>",
        #     host=host_pattern_path_style,
        #     endpoint=self.serve_bucket_content,
        #     # methods=["GET"] TODO if I enable this, put-object does not work anymore
        #     #                     raise MethodNotAllowed(valid_methods=list(have_match_for))
        #     #                     E       werkzeug.exceptions.MethodNotAllowed: 405 Method Not Allowed: The method is not allowed for the requested URL
        #     # defaults={"region": None}
        # )
        # virtual-host style: https://bucket-name.s3.region-code.amazonaws.com/key-name
        # host_pattern_vhost_style = f"{bucket}.s3.<regex('({AWS_REGION_REGEX}\.)?'):region>{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"
        host_pattern_vhost_style = f"{bucket}.s3.{LOCALHOST_HOSTNAME}:{get_edge_port_http()}"

        ROUTER.add(
            "/<path:path>",
            host=host_pattern_vhost_style,
            # defaults={"region": None},
            endpoint=self.serve_bucket_content,
            methods=["GET"],
        )
        ROUTER.add(
            "/",
            host=host_pattern_vhost_style,
            # defaults={"region": None},
            endpoint=self.serve_bucket_list,
            methods=["GET"],
        )

        return response

    def serve_bucket_list(self, request: Request) -> Response:
        bucket = request.url.split("://")[1].split(".")[0]
        if request.method == "GET":
            client = aws_stack.connect_to_service("s3")
            data = client.list_objects(Bucket=bucket)
            return data  # TODO this should return xml-response

    def serve_bucket_content(self, request: Request, path: str) -> Response:
        # bucket = request.path.split("/")[1]
        bucket = request.url.split("://")[1].split(".")[0]
        key = path
        # region = ?

        # somehow resolve the bucket key content
        if request.method == "GET":
            if key:
                client = aws_stack.connect_to_service("s3")
                data = client.get_object(Bucket=bucket, Key=key)
                return Response(data["Body"].read())

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

    def put_bucket_policy(
        self,
        context: RequestContext,
        bucket: BucketName,
        policy: Policy,
        content_md5: ContentMD5 = None,
        checksum_algorithm: ChecksumAlgorithm = None,
        confirm_remove_self_bucket_access: ConfirmRemoveSelfBucketAccess = None,
        expected_bucket_owner: AccountId = None,
    ) -> Response:
        response = proxy_moto(context)
        if response.status_code == 200:
            response.status_code = 204
        return response

    @handler("PutObject", expand=False)
    def put_object(self, context: RequestContext, request: PutObjectRequest) -> PutObjectOutput:
        if context.request.headers.get("x-amz-sdk-checksum-algorithm"):
            # TODO - data is gone after reading once
            # data = request.get("Body").read()
            data = b"test"
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
