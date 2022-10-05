import re
from typing import Dict, Optional

from localstack.aws.api import RequestContext
from localstack.aws.api.s3 import BucketName, CORSConfiguration, CORSRule
from localstack.aws.chain import Handler, HandlerChain
from localstack.config import DEFAULT_REGION
from localstack.http import Response

from ...utils.bootstrap import log_duration
from .models import s3_stores
from .utils import S3_VIRTUAL_HOSTNAME_REGEX

_s3_virtual_host_regex = re.compile(S3_VIRTUAL_HOSTNAME_REGEX)


class S3CorsHandler(Handler):
    _cors_index_cache: Optional[Dict[str, CORSConfiguration]]

    def __init__(self):
        self._cors_index_cache = None

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        self.handle_cors(chain, context, response)

    @log_duration(min_ms=0)
    def handle_cors(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not self.cors_index:
            # if there are no cors rules, we can just skip the checks
            # vhost matching is relatively expensive
            return

        bucket = None

        # try to extract the bucket from the hostname
        if match := _s3_virtual_host_regex.match(context.request.host):
            bucket = match.group(3)

        # if it's not a valid s3 hostname, then try the first path parameter
        if not bucket:
            path_parts = context.request.path.split("/")
            # 0 will always be empty, because the path is always prefixed with /
            bucket = path_parts[1]

            if not bucket:
                # this would be the case for http://localhost:4566/
                return

        if bucket not in self.cors_index:
            # either there is no CORS config, or the first path parameter is not actually a bucket
            return

        rules = self.cors_index[bucket]["CORSRules"]
        if not rules:
            return

        if len(rules) > 1:
            # TODO: consolidate multiple rules (join origins etc)
            raise NotImplementedError

        rule: CORSRule = rules[0]

        if allowed_origins := rule["AllowedOrigins"]:
            response.headers["Access-Control-Allow-Origin"] = ", ".join(allowed_origins)

        if allowed_methods := rule["AllowedMethods"]:
            response.headers["Access-Control-Allow-Methods"] = ", ".join(allowed_methods)

        if allowed_headers := rule["AllowedHeaders"]:
            response.headers["Access-Control-Allow-Headers"] = ", ".join(allowed_headers)

        if max_age_seconds := rule["MaxAgeSeconds"]:
            response.headers["Access-Control-Max-Age"] = str(max_age_seconds)

        # TODO: when is this set?
        response.headers["Access-Control-Allow-Credentials"] = "true"

        print(bucket, dict(response.headers))

        if context.request.method == "OPTIONS":
            response.set_response(b"")
            chain.stop()

    @property
    def cors_index(self) -> Dict[str, CORSConfiguration]:
        if self._cors_index_cache is None:
            self._cors_index_cache = self._build_cors_index()
        return self._cors_index_cache

    def invalidate_cache(self):
        self._cors_index_cache = None

    def _build_cors_index(self) -> Dict[BucketName, CORSConfiguration]:
        result = {}
        for account_id, regions in s3_stores.items():
            result.update(regions[DEFAULT_REGION].bucket_cors)

        return result
