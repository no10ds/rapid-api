import boto3


def athena_query(params):
    client = boto3.client("athena")
    response = client.start_query_execution(
        QueryString="DROP TABLE `playwright_playwright01`;",
        QueryExecutionContext={
            "Catalog": params["catalog"],
            "Database": params["database"],
        },
        ResultConfiguration={
            "OutputLocation": "s3://"
            + params["query_bucket"]
            + "/"
            + params["query_path"],
            "EncryptionConfiguration": {
                "EncryptionOption": "SSE_KMS",
                "KmsKey": "arn:aws:kms:"
                + params["region"]
                + ":"
                + params["account_id"]
                + ":key/"
                + params["kmskey"],
            },
            "ExpectedBucketOwner": params["account_id"],
            "AclConfiguration": {"S3AclOption": "BUCKET_OWNER_FULL_CONTROL"},
        },
    )
    return response
